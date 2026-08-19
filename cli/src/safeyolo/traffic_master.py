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
import urwid
from argon2 import PasswordHasher
from mitmproxy import options, optmanager
from mitmproxy.tools import cmdline, main
from mitmproxy.tools.console import common, statusbar
from mitmproxy.tools.console import signals as console_signals
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.tools.web import app, static_viewer, webaddons
from mitmproxy.utils import human

from .events import EventKind, Severity, write_event

log = logging.getLogger("safeyolo.traffic-master")


class SafeYoloStatusBar(statusbar.StatusBar):
    """Put evidence scope ahead of useful mitmproxy status indicators."""

    @staticmethod
    def _format_stream_threshold(value: str) -> str:
        size = human.parse_size(value)
        if size is None:
            return value
        for suffix, factor in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
            if size >= factor:
                return f"{size / factor:g} {suffix}"
        return f"{size} bytes"

    def get_status(self) -> list[tuple[str, str] | str]:
        scope = self.master.addons.get("traffic-scope")
        if scope is None:
            return super().get_status()
        state = scope.get_stats()
        agent = "unattributed" if state["unattributed"] else state["agent"] or "all agents"
        parts = [agent]
        parts.extend(
            value
            for value in (state["test_id"], state["intent"], state["role"], state["expect"])
            if value
        )
        pinned = " · ".join(parts)
        stock = super().get_status()
        modes = self.master.options.mode
        mode_indicator = f"[{modes[0]}]" if len(modes) == 1 else f"[modes:{len(modes)}]"
        scripts_indicator = f"[scripts:{len(self.master.options.scripts)}]"
        useful = [item for item in stock if item not in {mode_indicator, scripts_indicator}]
        stream_threshold = self.master.options.stream_large_bodies
        if stream_threshold:
            combined_suffix = f":{stream_threshold}]"
            cleaned = []
            for item in useful:
                if item == f"[{stream_threshold}]":
                    continue
                if isinstance(item, str) and item.endswith(combined_suffix):
                    item = f"{item[: -len(combined_suffix)]}]"
                cleaned.append(item)
            useful = cleaned
            useful.append(
                f"[stream≥{self._format_stream_threshold(stream_threshold)}]"
            )
        return [("heading_key", f"[SafeYolo · {pinned}]"), *useful]

    def redraw(self) -> None:
        """Render scope without exposing implementation-detail UDS paths."""
        flow_count = self.master.commands.execute("view.properties.length")
        if self.master.view.focus.index is None:
            offset = 0
        else:
            offset = self.master.view.focus.index + 1

        arrow = (
            common.SYMBOL_UP
            if self.master.options.view_order_reversed
            else common.SYMBOL_DOWN
        )
        marked = "M" if self.master.commands.execute("view.properties.marked") else ""
        text: list[tuple[str, str] | str] = [
            ("heading", f"{arrow} {marked} [{offset}/{flow_count}]".ljust(11)),
            *self.get_status(),
        ]
        self.ib._w = urwid.AttrMap(urwid.Text(text), "heading")


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


class ScopeStyleHandler(app.RequestHandler):
    def get(self) -> None:
        self.set_header("Content-Type", "text/css; charset=UTF-8")
        self.write(_SCOPE_STYLE)


class SafeYoloIndexHandler(app.IndexHandler):
    def get(self) -> None:
        _ = self.xsrf_token
        index_path = Path(app.__file__).with_name("index.html")
        html = index_path.read_text(encoding="utf-8")
        host = escape(socket.gethostname())
        self.write(html.replace("</head>", '<link rel="stylesheet" href="/safeyolo/scope.css"></head>').replace("<body>", f"<body>{_scope_toolbar(host)}"))

    post = get


def _scope_toolbar(host: str) -> str:
    return f"""
<section id="safeyolo-scope" aria-label="Pinned SafeYolo traffic scope">
  <div class="safeyolo-scope-heading"><strong>SafeYolo Traffic — {host}</strong><output data-scope-summary>Pinned: all agents · no test context</output></div>
  <div class="safeyolo-scope-controls">
    <label>Agent <select data-scope="agent" aria-label="Pinned agent"></select></label>
    <label>Test <select data-scope="test_id" aria-label="Pinned test"></select></label>
    <label>Intent <select data-scope="intent" aria-label="Pinned intent"></select></label>
    <label>Role <select data-scope="role" aria-label="Pinned role"></select></label>
    <label>Expect <select data-scope="expect" aria-label="Pinned expectation"></select></label>
  </div>
</section>
<script type="module" src="/safeyolo/scope.js"></script>
"""


_SCOPE_STYLE = r"""
#safeyolo-scope { position:relative; z-index:1000; box-sizing:border-box; padding:6px 10px; background:#fff; color:#333; font:14px/1.42857143 Arial,sans-serif; border-bottom:1px solid #a6a6a6; }
.safeyolo-scope-heading { display:flex; align-items:baseline; justify-content:space-between; gap:12px; margin-bottom:5px; }
#safeyolo-scope [data-scope-summary] { color:#777; overflow-wrap:anywhere; text-align:right; font-size:12px; }
.safeyolo-scope-controls { display:flex; flex-wrap:wrap; gap:6px 10px; align-items:center; }
.safeyolo-scope-controls label { display:flex; gap:5px; align-items:center; white-space:nowrap; color:#777; font-size:12px; font-weight:400; }
.safeyolo-scope-controls select { min-width:8rem; max-width:15rem; height:30px; padding:4px 8px; color:#333; background:#fff; border:1px solid #ccc; border-radius:4px; font:14px/1.42857143 Arial,sans-serif; }
.safeyolo-scope-controls select:focus-visible { outline:0; border-color:#66afe9; box-shadow:0 0 8px #66afe999; }
@media (max-width:600px) {
  .safeyolo-scope-heading { align-items:flex-start; flex-direction:column; gap:2px; }
  #safeyolo-scope [data-scope-summary] { text-align:left; }
  .safeyolo-scope-controls label { flex:1 1 9rem; }
  .safeyolo-scope-controls select { min-width:0; width:100%; }
}
"""


_SCOPE_SCRIPT = r"""
const mapping = {agent: "agent", test_id: "test_id", intent: "test_intent", role: "test_role", expect: "test_expect"};
const UNATTRIBUTED = '__safeyolo_unattributed__';
const cookie = name => document.cookie.split('; ').find(x => x.startsWith(name + '='))?.split('=').slice(1).join('=') || '';
async function scopeRequest(options) {
  const response = await fetch('/safeyolo/scope', options);
  if (response.status === 403) {
    window.location.assign('/');
    throw new Error('scope authentication expired; reloading login');
  }
  return response;
}
async function state() {
  const response = await scopeRequest();
  if (!response.ok) throw new Error(`scope read failed: ${response.status}`);
  return response.json();
}
async function render() {
  const data = await state();
  const pinned = [data.scope.unattributed ? 'unattributed' : (data.scope.agent || 'all agents')];
  for (const field of ['test_id', 'intent', 'role', 'expect']) if (data.scope[field]) pinned.push(data.scope[field]);
  const summary = document.querySelector('[data-scope-summary]');
  if (summary) summary.textContent = `Pinned: ${pinned.join(' · ')}${data.scope.user_filter ? ' · Search preserved' : ''}`;
  for (const select of document.querySelectorAll('[data-scope]')) {
    const field = select.dataset.scope;
    const facet = mapping[field];
    const current = field === 'agent' && data.scope.unattributed ? UNATTRIBUTED : (data.scope[field] || '');
    select.replaceChildren(new Option(field === 'agent' ? 'All agents' : 'No restriction', ''));
    if (field === 'agent') select.add(new Option('Unattributed traffic', UNATTRIBUTED));
    for (const item of data.facets[facet] || []) select.add(new Option(`${item.value} (${item.count})`, item.value));
    select.value = current;
    select.onchange = async () => {
      const body = {};
      const controls = [...document.querySelectorAll('[data-scope]')];
      const changed = controls.indexOf(select);
      for (const [index, control] of controls.entries()) {
        if (index > changed) {
          body[control.dataset.scope] = null;
          continue;
        }
        body[control.dataset.scope] = control.dataset.scope === 'agent' && control.value === UNATTRIBUTED ? null : (control.value || null);
      }
      body.unattributed = document.querySelector('[data-scope="agent"]').value === UNATTRIBUTED;
      const response = await scopeRequest({
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
setInterval(() => render().catch(error => console.error('SafeYolo scope refresh:', error)), 5000);
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
            write_event(
                "ops.proxy_start_failed",
                kind=EventKind.OPS,
                severity=Severity.HIGH,
                summary=message,
                addon="traffic-master",
                details={
                    "component": "web-frontend",
                    "host": self.master.options.web_host,
                    "port": self.master.options.web_port,
                    "errno": exc.errno,
                },
            )
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
        # Establish SafeYolo's live-traffic defaults before mitmproxy loads
        # config files and CLI options, which remain authoritative overrides.
        opts.update(
            view_order="time",
            view_order_reversed=True,
            console_focus_follow=True,
        )
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
        # Give the web flow list the same chronological reading order as the
        # native table while retaining mitmweb's TLS and resource icons.
        opts.update(
            web_columns=[
                "timestamp",
                "tls",
                "icon",
                "method",
                "version",
                "path",
                "status",
                "size",
                "time",
            ]
        )
        password_file = os.environ.get("SAFEYOLO_WEB_PASSWORD_FILE")
        if password_file:
            try:
                password = Path(password_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError(f"cannot read web password file: {exc}") from exc
            if not password:
                raise RuntimeError("web password file is empty")
            # Mitmweb verifies Argon2 hashes against the password entered by
            # the operator. Keep plaintext out of its option state.
            opts.update(web_password=PasswordHasher().hash(password))
        self.web_app = app.Application(self, self.options.web_debug)
        self.web_app.add_handlers(
            r".*$",
            [
                (r"/safeyolo/scope", ScopeAPIHandler),
                (r"/safeyolo/scope.js", ScopeScriptHandler),
                (r"/safeyolo/scope.css", ScopeStyleHandler),
                (r"/", SafeYoloIndexHandler),
            ],
        )
        self.addons.add(WebFrontend(self))
        self._add_scope_keys()

    def _add_scope_keys(self) -> None:
        # The stock binding edits view_filter, which includes SafeYolo's
        # generated pinned scope. Present only the viewer-owned subfilter.
        self.keymap.remove("f", ["flowlist"])
        self.keymap.add(
            "f",
            "safeyolo.traffic.filter.edit",
            ["flowlist"],
            "Set view filter",
        )
        bindings = (
            ("\\", 'console.choose.cmd "SafeYolo agent" safeyolo.traffic.agent.options safeyolo.traffic.agent.set {choice}', "Choose SafeYolo agent"),
            ("[", "safeyolo.traffic.agent.prev", "Previous SafeYolo agent"),
            ("]", "safeyolo.traffic.agent.next", "Next SafeYolo agent"),
            ("0", "safeyolo.traffic.agent.all", "Show all SafeYolo agents"),
            ("9", "safeyolo.traffic.agent.unattributed", "Show unattributed SafeYolo traffic"),
            ("}", "safeyolo.traffic.test.choose", "Choose SafeYolo test context"),
            ("{", "safeyolo.traffic.test.clear", "Clear SafeYolo test context"),
            ("ctrl 0", "safeyolo.traffic.scope.clear", "Clear all SafeYolo scopes"),
        )
        for key, command_text, help_text in bindings:
            if self.keymap.get("global", key) is None:
                self.keymap.add(key, command_text, ["global"], help_text)

    async def running(self) -> None:
        await super().running()
        if self.window is not None:
            native_status = SafeYoloStatusBar(self)
            self.window.statusbar = native_status
            self.window.footer = urwid.AttrMap(native_status, "background")
        # ConsoleMaster dispatches addon running hooks in registration order;
        # WebFrontend may therefore fail after pid_writer has run. Publish the
        # PID only here, once every addon (including the web listener) is live.
        pid_writer = self.addons.get("pid-writer")
        if pid_writer is not None:
            pid_writer.signal_ready()

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
