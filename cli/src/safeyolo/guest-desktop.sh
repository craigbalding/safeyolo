#!/bin/bash
# SafeYolo-managed optional guest desktop.
#
# The rootfs supplies graphical packages; SafeYolo supplies lifecycle and the
# operator-facing preview.  This script is staged at /safeyolo/guest-desktop
# for every agent run, so custom rootfs builders do not need their own copy.
set -euo pipefail

DISPLAY_NUM=99
VNC_PORT=5900
NOVNC_PORT=6080
GEOMETRY_FILE=/tmp/safeyolo-vnc-geometry
DBUS_ENV=/tmp/safeyolo-dbus-env
DBUS_PID_FILE=/tmp/safeyolo-dbus.pid
FLUXBOX_CONFIG_DIR=/tmp/safeyolo-fluxbox
OPENBOX_CONFIG_DIR=/tmp/safeyolo-openbox
WINDOW_MANAGER_FILE=/tmp/safeyolo-window-manager

export DISPLAY=":${DISPLAY_NUM}"
export PATH="/home/agent/.local/bin:${PATH}"

_port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

_is_ready() {
    [ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] \
        && _port_open "$VNC_PORT" \
        && _port_open "$NOVNC_PORT"
}

_wait_for() {
    local description="$1" log_path="$2" probe="$3"
    local _
    for _ in $(seq 1 40); do
        if eval "$probe"; then
            return 0
        fi
        sleep 0.25
    done
    echo "error: ${description} did not become ready (log: ${log_path})" >&2
    return 1
}

_find_web_root() {
    local candidate
    for candidate in /usr/share/novnc /usr/share/webapps/novnc; do
        if [ -f "$candidate/vnc.html" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

_find_window_manager() {
    local candidate
    for candidate in fluxbox openbox; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

_find_terminal() {
    local candidate
    for candidate in xterm xfce4-terminal lxterminal; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

_find_browser() {
    local candidate
    for candidate in chromium chromium-browser google-chrome; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

_check_capability() {
    local missing=() command_name
    for command_name in Xvfb x11vnc websockify setsid pkill seq; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    _find_window_manager >/dev/null || missing+=("window manager (fluxbox or openbox)")
    _find_web_root >/dev/null || missing+=("noVNC web assets (vnc.html)")

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "desktop capability unavailable; the agent rootfs is missing:" >&2
        for command_name in "${missing[@]}"; do
            echo "  - ${command_name}" >&2
        done
        echo "Install a desktop-capable rootfs; SafeYolo will not install guest packages automatically." >&2
        return 127
    fi
}

_configure_fluxbox() {
    mkdir -p "$FLUXBOX_CONFIG_DIR"
    printf '%s\n' 'background: unset' >"$FLUXBOX_CONFIG_DIR/overlay"
    cat >"$FLUXBOX_CONFIG_DIR/init" <<EOF
session.menuFile: $FLUXBOX_CONFIG_DIR/menu
session.styleOverlay: $FLUXBOX_CONFIG_DIR/overlay
session.screen0.rootCommand: /bin/true
session.screen0.workspaceNames: Apps: right-click desktop,
session.screen0.toolbar.visible: true
session.screen0.toolbar.tools: workspacename, iconbar, systemtray, clock
EOF
    cat >"$FLUXBOX_CONFIG_DIR/menu" <<'EOF'
[begin] (SafeYolo Desktop)
EOF
    if _find_terminal >/dev/null; then
        cat >>"$FLUXBOX_CONFIG_DIR/menu" <<'EOF'
  [exec] (Terminal) {/safeyolo/guest-desktop terminal}
EOF
    fi
    if _find_browser >/dev/null; then
        cat >>"$FLUXBOX_CONFIG_DIR/menu" <<'EOF'
  [exec] (Browser) {/safeyolo/guest-desktop browser about:blank}
EOF
    fi
    cat >>"$FLUXBOX_CONFIG_DIR/menu" <<'EOF'
[end]
EOF
}

_configure_openbox() {
    local system_rc=""
    mkdir -p "$OPENBOX_CONFIG_DIR"
    cat >"$OPENBOX_CONFIG_DIR/menu.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="SafeYolo Desktop">
EOF
    if _find_terminal >/dev/null; then
        cat >>"$OPENBOX_CONFIG_DIR/menu.xml" <<'EOF'
    <item label="Terminal"><action name="Execute"><command>/safeyolo/guest-desktop terminal</command></action></item>
EOF
    fi
    if _find_browser >/dev/null; then
        cat >>"$OPENBOX_CONFIG_DIR/menu.xml" <<'EOF'
    <item label="Browser"><action name="Execute"><command>/safeyolo/guest-desktop browser about:blank</command></action></item>
EOF
    fi
    cat >>"$OPENBOX_CONFIG_DIR/menu.xml" <<'EOF'
  </menu>
</openbox_menu>
EOF

    for system_rc in /etc/xdg/openbox/rc.xml /usr/share/openbox/rc.xml; do
        [ -r "$system_rc" ] && break
        system_rc=""
    done
    if [ -n "$system_rc" ]; then
        cp "$system_rc" "$OPENBOX_CONFIG_DIR/rc.xml"
        sed -E -i \
            "s|<file>[^<]*menu.xml</file>|<file>$OPENBOX_CONFIG_DIR/menu.xml</file>|g" \
            "$OPENBOX_CONFIG_DIR/rc.xml"
    else
        cat >"$OPENBOX_CONFIG_DIR/rc.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <menu><file>$OPENBOX_CONFIG_DIR/menu.xml</file></menu>
  <mouse><context name="Root"><mousebind button="Right" action="Press"><action name="ShowMenu"><menu>root-menu</menu></action></mousebind></context></mouse>
</openbox_config>
EOF
    fi
}

_stop() {
    pkill -f "websockify.*${NOVNC_PORT}" 2>/dev/null || true
    pkill -f "x11vnc -display :${DISPLAY_NUM}" 2>/dev/null || true
    pkill -f "Xvfb :${DISPLAY_NUM}" 2>/dev/null || true
    pkill -x fluxbox 2>/dev/null || true
    pkill -x openbox 2>/dev/null || true
    if [ -r "$DBUS_PID_FILE" ]; then
        kill "$(cat "$DBUS_PID_FILE")" 2>/dev/null || true
    fi
    rm -f \
        "/tmp/.X${DISPLAY_NUM}-lock" \
        "/tmp/.X11-unix/X${DISPLAY_NUM}" \
        "$DBUS_ENV" "$DBUS_PID_FILE" "$GEOMETRY_FILE" \
        "$WINDOW_MANAGER_FILE"
}

_start_dbus() {
    local output address pid
    command -v dbus-daemon >/dev/null 2>&1 || return 0

    if command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p /run/dbus /var/lib/dbus 2>/tmp/dbus-system.log || true
        if command -v dbus-uuidgen >/dev/null 2>&1; then
            sudo dbus-uuidgen --ensure=/var/lib/dbus/machine-id \
                >>/tmp/dbus-system.log 2>&1 || true
        fi
        if [ ! -S /run/dbus/system_bus_socket ]; then
            sudo dbus-daemon --system --fork --nopidfile \
                >>/tmp/dbus-system.log 2>&1 || true
        fi
    fi

    output="$(dbus-daemon --session --fork --print-address=1 --print-pid=1 \
        2>/tmp/dbus.log || true)"
    address="$(printf '%s\n' "$output" | sed -n '1p')"
    pid="$(printf '%s\n' "$output" | sed -n '2p')"
    if [ -n "$address" ]; then
        printf 'export DBUS_SESSION_BUS_ADDRESS=%q\n' "$address" >"$DBUS_ENV"
        export DBUS_SESSION_BUS_ADDRESS="$address"
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$pid" >"$DBUS_PID_FILE"
    fi
}

_start() {
    local configured_geometry=""
    if [ -r /safeyolo/desktop-size ]; then
        configured_geometry="$(head -n 1 /safeyolo/desktop-size)"
    fi
    local geometry="${1:-${VNC_GEOMETRY:-${configured_geometry:-1280x800}}}"
    local depth="${VNC_DEPTH:-24}" width height current=""
    local web_root window_manager agent_name managed_window_manager=""

    if [[ "$geometry" =~ ^([0-9]+)x([0-9]+)(x([0-9]+))?$ ]]; then
        width="${BASH_REMATCH[1]}"
        height="${BASH_REMATCH[2]}"
        depth="${BASH_REMATCH[4]:-${depth}}"
    else
        echo "usage: guest-desktop start [WIDTHxHEIGHT]" >&2
        return 2
    fi

    _check_capability
    if [ -r "$GEOMETRY_FILE" ]; then
        current="$(tr ' ' x <"$GEOMETRY_FILE")"
    fi
    window_manager="$(_find_window_manager)"
    if _is_ready && [ "$current" = "${width}x${height}" ]; then
        [ -r "$WINDOW_MANAGER_FILE" ] && \
            managed_window_manager="$(cat "$WINDOW_MANAGER_FILE")"
        if [ "$managed_window_manager" = "$window_manager" ]; then
            # Refresh discovery after an agent installs a browser or terminal.
            # Fluxbox automatically rereads its menu when the file changes;
            # Openbox needs an explicit reconfigure request.
            if [ "$window_manager" = fluxbox ]; then
                _configure_fluxbox
            else
                _configure_openbox
                openbox --reconfigure >/tmp/window-manager-reconfigure.log 2>&1 \
                    || true
            fi
            echo "desktop already ready on 127.0.0.1:${NOVNC_PORT} (${width}x${height})"
            return 0
        fi
        echo "desktop uses legacy window-manager configuration; restarting" >&2
    fi

    web_root="$(_find_web_root)"
    _stop
    printf '%s %s\n' "$width" "$height" >"$GEOMETRY_FILE"
    _start_dbus

    setsid Xvfb ":${DISPLAY_NUM}" -screen 0 "${width}x${height}x${depth}" \
        </dev/null >/tmp/xvfb.log 2>&1 &
    _wait_for "Xvfb display :${DISPLAY_NUM}" /tmp/xvfb.log \
        "[ -S /tmp/.X11-unix/X${DISPLAY_NUM} ]"

    if [ "$window_manager" = fluxbox ]; then
        # Fluxbox's distro defaults try to restore a wallpaper through
        # fbsetbg, which shows an X11 warning when no wallpaper helper is
        # installed. SafeYolo needs only a quiet, minimal window manager.
        # Use an isolated configuration so we do not alter the agent's own
        # ~/.fluxbox settings; `background: unset` disables style wallpaper
        # commands while leaving ordinary window decoration intact.
        _configure_fluxbox
        setsid fluxbox -rc "$FLUXBOX_CONFIG_DIR/init" \
            </dev/null >/tmp/window-manager.log 2>&1 &
    else
        _configure_openbox
        setsid openbox --config-file "$OPENBOX_CONFIG_DIR/rc.xml" \
            </dev/null >/tmp/window-manager.log 2>&1 &
    fi
    printf '%s\n' "$window_manager" >"$WINDOW_MANAGER_FILE"

    setsid x11vnc -display ":${DISPLAY_NUM}" -nopw -listen 127.0.0.1 \
        -rfbport "$VNC_PORT" -forever -shared \
        -noxdamage -noxfixes -noscr -nowf -threads \
        </dev/null >/tmp/x11vnc.log 2>&1 &
    _wait_for "x11vnc on 127.0.0.1:${VNC_PORT}" /tmp/x11vnc.log \
        "_port_open ${VNC_PORT}"

    setsid websockify --web "$web_root" \
        "127.0.0.1:${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" \
        </dev/null >/tmp/websockify.log 2>&1 &
    _wait_for "noVNC on 127.0.0.1:${NOVNC_PORT}" /tmp/websockify.log \
        "_port_open ${NOVNC_PORT}"

    agent_name="$(cat /safeyolo/agent-name 2>/dev/null || echo '<name>')"
    echo "desktop ready in agent '${agent_name}' on 127.0.0.1:${NOVNC_PORT} (${width}x${height})"
    if [ "${SAFEYOLO_PREVIEW_MANAGED:-0}" != "1" ]; then
        echo "From the host: safeyolo agent desktop ${agent_name} --open"
    fi
}

_status() {
    local geometry="unknown"
    if [ -r "$GEOMETRY_FILE" ]; then
        geometry="$(tr ' ' x <"$GEOMETRY_FILE")"
    fi
    if _is_ready; then
        echo "desktop: ready (display :${DISPLAY_NUM}, ${geometry}, noVNC 127.0.0.1:${NOVNC_PORT})"
        return 0
    fi
    echo "desktop: stopped or incomplete" >&2
    [ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] \
        && echo "  Xvfb: ready" >&2 || echo "  Xvfb: down" >&2
    _port_open "$VNC_PORT" \
        && echo "  x11vnc: ready" >&2 || echo "  x11vnc: down" >&2
    _port_open "$NOVNC_PORT" \
        && echo "  noVNC: ready" >&2 || echo "  noVNC: down" >&2
    return 1
}

_browser() {
    local url="${1:-}" browser="" proxy="${HTTPS_PROXY:-${HTTP_PROXY:-}}"
    local profile="${HOME}/.cache/safeyolo-browser/profile"
    local nssdb="${HOME}/.pki/nssdb"
    local ca="${SSL_CERT_FILE:-/usr/local/share/ca-certificates/safeyolo.crt}"
    local window_size="1280,800" width height
    local -a args
    [ -n "$url" ] || { echo "usage: guest-desktop browser URL" >&2; return 2; }
    _is_ready || { echo "error: start the desktop before launching a browser" >&2; return 1; }
    [ -r "$DBUS_ENV" ] && source "$DBUS_ENV"

    browser="$(_find_browser || true)"
    if [ -z "$browser" ]; then
        echo "browser capability unavailable; install Chromium in the agent rootfs" >&2
        return 127
    fi

    if [ -r "$GEOMETRY_FILE" ]; then
        read -r width height <"$GEOMETRY_FILE" || true
        window_size="${width:-1280},${height:-800}"
    fi

    # Chromium uses an NSS database on Linux. Import SafeYolo's current CA so
    # HTTPS browsing works through the enforced proxy without weakening TLS.
    if [ -r "$ca" ] && command -v certutil >/dev/null 2>&1; then
        mkdir -p "$nssdb"
        if [ ! -f "$nssdb/cert9.db" ]; then
            certutil -d "sql:${nssdb}" -N --empty-password \
                >/tmp/chrome-certutil.log 2>&1 || true
        fi
        certutil -d "sql:${nssdb}" -D -n "SafeYolo MITM Proxy" \
            >/dev/null 2>&1 || true
        certutil -d "sql:${nssdb}" -A -t "C,," \
            -n "SafeYolo MITM Proxy" -i "$ca" \
            >/tmp/chrome-certutil.log 2>&1 \
            || echo "warning: failed to import SafeYolo CA into ${nssdb}" >&2
    fi

    mkdir -p "$profile"
    args=(
        --no-sandbox
        --disable-dev-shm-usage
        --disable-gpu
        --disable-gpu-compositing
        --disable-gpu-rasterization
        --disable-accelerated-2d-canvas
        --disable-vulkan
        --use-gl=disabled
        --ozone-platform=x11
        --no-first-run
        --no-default-browser-check
        "--user-data-dir=${profile}"
        --remote-debugging-address=127.0.0.1
        --remote-debugging-port=9222
        --start-maximized
        --window-position=0,0
        "--window-size=${window_size}"
        --password-store=basic
    )
    [ -n "$proxy" ] && args+=("--proxy-server=${proxy}")
    [ -n "${NO_PROXY:-}" ] && args+=("--proxy-bypass-list=${NO_PROXY//,/;}")
    setsid "$browser" "${args[@]}" "$url" </dev/null >/tmp/chrome.log 2>&1 &
    _wait_for "${browser} debugging endpoint on 127.0.0.1:9222" \
        /tmp/chrome.log "_port_open 9222"
    echo "browser ready with ${browser} (log: /tmp/chrome.log)"
}

_terminal() {
    local terminal=""
    _is_ready || { echo "error: start the desktop before launching a terminal" >&2; return 1; }
    [ -r "$DBUS_ENV" ] && source "$DBUS_ENV"
    terminal="$(_find_terminal || true)"
    if [ -z "$terminal" ]; then
        echo "terminal capability unavailable; install xterm in the agent rootfs" >&2
        return 127
    fi
    case "$terminal" in
        xterm)
            setsid xterm -ls -title "SafeYolo Agent Terminal" \
                </dev/null >/tmp/terminal.log 2>&1 &
            ;;
        *)
            setsid "$terminal" </dev/null >/tmp/terminal.log 2>&1 &
            ;;
    esac
    echo "terminal ready with ${terminal} (log: /tmp/terminal.log)"
}

action="${1:-start}"
shift || true
case "$action" in
    check) _check_capability ;;
    start) _start "$@" ;;
    status) _status ;;
    stop)
        _stop
        echo "desktop stopped"
        ;;
    browser) _browser "$@" ;;
    terminal) _terminal ;;
    *)
        echo "usage: guest-desktop {check|start [WIDTHxHEIGHT]|status|stop|browser URL|terminal}" >&2
        exit 2
        ;;
esac
