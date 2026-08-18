"""SafeYolo's single-master native console and mitmweb process."""

from __future__ import annotations

import errno
import logging
import os
import socket
import sys
from html import escape
from pathlib import Path
from typing import Any

import tornado.httpserver
import tornado.ioloop
from mitmproxy import options, optmanager
from mitmproxy.tools import cmdline, main
from mitmproxy.tools.console import signals as console_signals
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.tools.web import app, static_viewer, webaddons

log = logging.getLogger("safeyolo.traffic-master")


class ScopeAPIHandler(app.RequestHandler):
    def _scope_addon(self):
        return self.master.addons.get("traffic-scope")

    def get(self) -> None:
        addon = self._scope_addon()
        self.write({"scope": addon.get_stats(), "facets": addon.facet_values()})

    def put(self) -> None:
        allowed = {"agent", "unattributed", "test_id", "intent", "role", "expect"}
        unknown = sorted(set(self.json) - allowed)
        if unknown:
            raise app.APIError(400, f"unknown scope field(s): {', '.join(unknown)}")
        self.write({"scope": self._scope_addon().set_scope(**self.json)})


class ScopeScriptHandler(app.RequestHandler):
    def get(self) -> None:
        self.set_header("Content-Type", "text/javascript; charset=UTF-8")
        self.write(_SCOPE_SCRIPT)


class SafeYoloIndexHandler(app.IndexHandler):
    def get(self) -> None:
        _ = self.xsrf_token
        index_path = Path(app.__file__).with_name("index.html")
        html = index_path.read_text(encoding="utf-8")
        host = escape(socket.gethostname())
        toolbar = f"""
<div id="safeyolo-scope" style="height:42px;padding:6px 10px;background:#17212b;color:#fff;display:flex;gap:8px;align-items:center;font:13px sans-serif">
  <strong>SafeYolo Traffic — {host}</strong>
  <label>Agent <select data-scope="agent"></select></label>
  <label>Test <select data-scope="test_id"></select></label>
  <label>Intent <select data-scope="intent"></select></label>
  <label>Role <select data-scope="role"></select></label>
  <label>Expect <select data-scope="expect"></select></label>
</div>
<script type="module" src="/safeyolo/scope.js"></script>
"""
        self.write(
            html.replace(
                "<body>",
                f'<body style="padding-top:42px">{toolbar}',
            )
        )

    post = get


_SCOPE_SCRIPT = r"""
const mapping = {agent: "agent", test_id: "test_id", intent: "test_intent", role: "test_role", expect: "test_expect"};
const cookie = name => document.cookie.split('; ').find(x => x.startsWith(name + '='))?.split('=').slice(1).join('=') || '';
async function state() {
  const response = await fetch('/safeyolo/scope');
  if (!response.ok) throw new Error(`scope read failed: ${response.status}`);
  return response.json();
}
async function render() {
  const data = await state();
  for (const select of document.querySelectorAll('[data-scope]')) {
    const field = select.dataset.scope;
    const facet = mapping[field];
    const current = data.scope[field] || '';
    select.replaceChildren(new Option('All', ''));
    for (const item of data.facets[facet] || []) select.add(new Option(`${item.value} (${item.count})`, item.value));
    select.value = current;
    select.onchange = async () => {
      const body = {};
      for (const control of document.querySelectorAll('[data-scope]')) body[control.dataset.scope] = control.value || null;
      body.unattributed = false;
      const response = await fetch('/safeyolo/scope', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json', 'X-XSRFToken': decodeURIComponent(cookie('_mitmproxy_xsrf') || cookie('_xsrf'))},
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`scope update failed: ${response.status}`);
      await render();
    };
  }
}
render().catch(error => console.error('SafeYolo scope controls:', error));
"""


class WebFrontend:
    """Attach mitmweb's listener and broadcasts to a ConsoleMaster."""

    name = "safeyolo-web-frontend"

    def __init__(self, master: TrafficMaster) -> None:
        self.master = master
        self.server: tornado.httpserver.HTTPServer | None = None
        master.view.sig_view_add.connect(self.view_add)
        master.view.sig_view_remove.connect(self.view_remove)
        master.view.sig_view_update.connect(self.view_update)
        master.view.sig_view_refresh.connect(self.view_refresh)
        master.events.sig_add.connect(self.event_add)
        master.events.sig_refresh.connect(self.event_refresh)
        master.options.changed.connect(self.options_update)
        master.proxyserver.servers.changed.connect(self.servers_update)

    def view_add(self, flow: Any) -> None:
        app.ClientConnection.broadcast_flow("flows/add", flow)

    def view_remove(self, flow: Any, _index: int) -> None:
        app.ClientConnection.broadcast(type="flows/remove", payload=flow.id)

    def view_update(self, flow: Any) -> None:
        app.ClientConnection.broadcast_flow("flows/update", flow)

    def view_refresh(self) -> None:
        app.ClientConnection.broadcast_flow_reset()

    def event_add(self, entry: Any) -> None:
        app.ClientConnection.broadcast(
            type="events/add",
            payload=app.logentry_to_json(entry),
        )

    def event_refresh(self) -> None:
        app.ClientConnection.broadcast(type="events/reset")

    def options_update(self, updated: set[str]) -> None:
        app.ClientConnection.broadcast(
            type="options/update",
            payload=optmanager.dump_dicts(self.master.options, updated),
        )

    def servers_update(self) -> None:
        app.ClientConnection.broadcast(
            type="state/update",
            payload={
                "servers": {server.mode.full_spec: server.to_json() for server in self.master.proxyserver.servers}
            },
        )

    async def running(self) -> None:
        tornado.ioloop.IOLoop.current()
        self.server = tornado.httpserver.HTTPServer(
            self.master.web_app,
            max_buffer_size=2**32,
        )
        try:
            self.server.listen(
                self.master.options.web_port,
                self.master.options.web_host,
            )
        except OSError as exc:
            message = (
                f"Web server failed to listen on {self.master.options.web_host}:{self.master.options.web_port}: {exc}"
            )
            if exc.errno == errno.EADDRINUSE:
                message += " (address already in use)"
            raise OSError(exc.errno, message, exc.filename) from exc
        auth = self.master.addons.get("webauth")
        log.info("Shared traffic web UI listening at %s", auth.web_url)

    async def done(self) -> None:
        if self.server is not None:
            self.server.stop()
            await self.server.close_all_connections()


class TrafficMaster(ConsoleMaster):
    """One canonical flow store with native console and web frontends."""

    def __init__(self, opts: options.Options) -> None:
        super().__init__(opts)
        # mitmproxy's stock uppercase-Q binding bypasses prompt_for_exit and
        # shuts the master down immediately.  Keep shutdown an explicit
        # lifecycle action so a viewer cannot accidentally stop the proxy.
        self.keymap.remove("Q", ["global"])
        self.proxyserver = self.addons.get("proxyserver")
        self.addons.add(
            webaddons.WebAddon(),
            webaddons.WebAuth(),
            static_viewer.StaticViewer(),
        )
        password_file = os.environ.get("SAFEYOLO_WEB_PASSWORD_FILE")
        if password_file:
            try:
                password = Path(password_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError(f"cannot read web password file: {exc}") from exc
            if not password:
                raise RuntimeError("web password file is empty")
            opts.update(web_password=password)
        self.web_app = app.Application(self, self.options.web_debug)
        self.web_app.add_handlers(
            r".*$",
            [
                (r"/safeyolo/scope", ScopeAPIHandler),
                (r"/safeyolo/scope.js", ScopeScriptHandler),
                (r"/", SafeYoloIndexHandler),
            ],
        )
        self.addons.add(WebFrontend(self))

    def prompt_for_exit(self) -> None:
        """Keep ordinary console back/quit keys from stopping the data plane."""
        console_signals.status_message.send(
            message="Detach with tmux prefix+d; stop with `safeyolo stop`.",
            expire=5,
        )


def main_entry(arguments: list[str] | None = None) -> None:
    """Run the hybrid master using mitmproxy's native CLI processing."""
    main.run(TrafficMaster, cmdline.mitmproxy, sys.argv[1:] if arguments is None else arguments)


if __name__ == "__main__":
    main_entry()
