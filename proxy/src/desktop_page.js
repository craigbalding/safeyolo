/* This outer page owns connection attempts. noVNC owns only the current viewer. */
(() => {
    'use strict';
    const base = '/_safeyolo_desktop/';
    const byId = id => document.getElementById(id);
    const log = [];
    let rfb = null, channel = null, RFB = null, viewerId = null;
    let epoch = 0, controller = null, timer = null, handshakeTimer = null;
    let busy = false, queued = false, closed = false, terminal = false;
    let connected = false, connecting = false, loading = false;
    let failures = 0, retryAt = 0, lastTick = Date.now(), lastContact = null;
    let lastObservation = null, noGreetingCount = 0, failedStage = null;
    let disagreement = false, pageActive = true;

    function attemptId() {
        // getRandomValues also works on existing HTTP Tailnet previews.
        // randomUUID is available only in secure browser contexts.
        return Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, '0')).join('');
    }

    function record(stage, outcome, duration = null) {
        // All text comes from the fixed checks below. Never copy guest error
        // strings, URLs, credentials, clipboard content or pixels into this log.
        const elapsed = Number.isFinite(duration) ? ` (${Math.round(duration)} ms)` : '';
        log.push(`${new Date().toISOString()}  ${stage}: ${outcome}${elapsed}`);
        if (log.length > 120) log.shift();
        byId('log').textContent = log.join('\n');
    }
    function status(title, explanation = '') {
        byId('status').textContent = title;
        byId('explanation').textContent = explanation;
    }
    function controls() {
        for (const id of ['fullscreen', 'ctrlaltdelete', 'escape', 'tab', 'ctrl', 'alt', 'super', 'send-clipboard']) {
            byId(id).disabled = !connected;
        }
    }
    function settings() {
        if (!rfb) return;
        rfb.scaleViewport = byId('scale').checked;
        rfb.resizeSession = byId('resize').checked;
        rfb.viewOnly = byId('viewonly').checked;
        rfb.clipViewport = byId('drag').checked;
        rfb.dragViewport = byId('drag').checked;
    }
    function dispose() {
        epoch++;
        clearTimeout(handshakeTimer);
        handshakeTimer = null;
        const old = rfb, oldChannel = channel;
        rfb = null; channel = null; viewerId = null;
        connected = false; connecting = false;
        for (const id of ['ctrl', 'alt', 'super']) byId(id).setAttribute('aria-pressed', 'false');
        byId('credentials').hidden = true;
        byId('verification').hidden = true;
        byId('password').value = '';
        if (old) { try { old.disconnect(); } catch (_) { /* close the channel below */ } }
        if (oldChannel) { try { oldChannel.close(); } catch (_) { /* already closed */ } }
        byId('screen').replaceChildren();
        controls();
    }
    function fail(stage) {
        if (closed || terminal || !pageActive) return;
        failedStage = stage;
        record(stage, 'failed; old viewer closed');
        dispose();
        failures++;
        const seconds = Math.min(30, 2 ** Math.min(failures - 1, 5));
        retryAt = Date.now() + seconds * 1000;
        record('Retry', failures >= 8 ? 'paused after 8 failed attempts; use Check again' : `fresh checks required; backoff ${seconds} seconds`);
        status('Desktop connection interrupted — checking', 'The failing stage is being checked.');
        wake();
    }
    function accessFailure(code) {
        terminal = true;
        dispose();
        if (code === 401) {
            status('Preview unlock required', 'Use the existing unlock page to renew access.');
            byId('unlock').hidden = false;
        } else if (code === 410) {
            status('Preview target was removed or replaced', 'Open a new desktop presentation for the intended agent.');
        } else {
            status('Preview access refused', 'This page has stopped connection attempts.');
        }
        record('Preview access', `authoritative HTTP ${code}; retries stopped`);
        clearTimeout(timer);
    }
    async function get(path, signal, timeout = 14000) {
        const own = new AbortController();
        const abort = () => own.abort();
        signal.addEventListener('abort', abort, {once: true});
        const deadline = setTimeout(abort, timeout);
        const began = performance.now();
        let replied = false;
        try {
            const response = await fetch(base + path, {credentials: 'same-origin', cache: 'no-store', signal: own.signal});
            if (signal.aborted || closed || !pageActive) return null;
            replied = true;
            lastContact = Date.now();
            record('Browser → SafeYolo', `intended endpoint replied HTTP ${response.status}`, performance.now() - began);
            if ([401, 403, 410].includes(response.status)) { accessFailure(response.status); return null; }
            if (!response.ok || !(response.headers.get('content-type') || '').startsWith('application/json')) {
                throw new Error('diagnostic response unavailable');
            }
            const value = await response.json();
            if (signal.aborted) return null;
            byId('contact').textContent = `Last SafeYolo contact: ${new Date(lastContact).toLocaleTimeString()}. Server observations are current.`;
            return value;
        } catch (error) {
            if (replied) {
                const unavailable = new Error('origin replied without a usable observation');
                unavailable.originReplied = true;
                throw unavailable;
            }
            throw error;
        } finally {
            clearTimeout(deadline);
            signal.removeEventListener('abort', abort);
        }
    }
    async function loadViewer(signal) {
        if (RFB) return true;
        loading = true;
        // An attempt prefix also versions relative imports. A failed module
        // fetch must not poison later asset recovery in the browser module map.
        let deadline;
        try {
            const attempt = attemptId();
            const module = await Promise.race([
                import(`${base}assets/${attempt}/core/rfb.js`),
                new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('asset deadline')), 20000); }),
            ]);
            if (signal.aborted || closed || terminal || !pageActive) return false;
            RFB = module.default;
            record('Viewer assets', 'noVNC RFB library loaded');
            return true;
        } catch (_) {
            if (!signal.aborted) fail('Viewer assets or initialization');
            return false;
        } finally { clearTimeout(deadline); loading = false; }
    }
    async function connect(signal) {
        if (connected || connecting || loading || closed || terminal || failures >= 8 || Date.now() < retryAt) return;
        if (!await loadViewer(signal)) return;
        if (signal.aborted) return;
        dispose();
        const attemptEpoch = epoch;
        connecting = true;
        failedStage = 'WebSocket/relay establishment';
        status('Connecting desktop', 'The viewer has a 20-second handshake deadline.');
        record('Viewer', 'new shared connection; handshake deadline 20 seconds');
        const current = () => attemptEpoch === epoch && pageActive && !closed && !terminal;
        const handshakeDeadline = () => {
            clearTimeout(handshakeTimer);
            handshakeTimer = setTimeout(() => { if (current() && !connected) fail(failedStage || 'RFB handshake'); }, 20000);
        };
        try {
            viewerId = attemptId();
            const url = new URL(base + 'viewer?' + viewerId, location.href);
            url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            channel = new WebSocket(url, ['binary']);
            channel.binaryType = 'arraybuffer';
            channel.addEventListener('open', () => {
                if (current()) { failedStage = 'RFB handshake'; record('WebSocket/relay', 'upgrade completed; handshake still required'); }
            });
            rfb = new RFB(byId('screen'), channel, {shared: true});
            settings();
            rfb.addEventListener('connect', () => {
                if (!current()) return;
                connected = true; connecting = false; failedStage = null; failures = 0;
                clearTimeout(handshakeTimer);
                record('RFB handshake', 'connected; application responsiveness is unverified');
                status(disagreement ? 'Desktop connected — recorded agent state differs' : 'Desktop connected', 'The viewer remains in this page.');
                controls();
            });
            rfb.addEventListener('disconnect', () => { if (current()) fail(failedStage || 'Existing viewer connection'); });
            rfb.addEventListener('securityfailure', () => { if (current()) fail('RFB security negotiation'); });
            rfb.addEventListener('credentialsrequired', () => {
                if (!current()) return;
                clearTimeout(handshakeTimer);
                byId('credentials').hidden = false;
                record('RFB security', 'credentials requested; no credential content recorded');
                status('Desktop credentials required', 'Enter the desktop credentials below.');
            });
            rfb.addEventListener('serververification', async event => {
                if (!current()) return;
                clearTimeout(handshakeTimer);
                status('Desktop server verification required', 'Compare the fingerprint with your desktop server before connecting.');
                record('RFB security', 'server identity needs user verification');
                try {
                    if (event.detail.type !== 'RSA' || event.detail.publickey.byteLength > 4096) throw new Error('unsupported server key');
                    // Match the fingerprint shown by the shipped noVNC UI.
                    const digest = await crypto.subtle.digest('SHA-1', event.detail.publickey);
                    if (!current()) return;
                    byId('fingerprint').textContent = Array.from(new Uint8Array(digest).slice(0, 8), value => value.toString(16).padStart(2, '0')).join('-');
                    byId('verification').hidden = false;
                } catch (_) { if (current()) fail('RFB server verification unavailable'); }
            });
            rfb.addEventListener('clipboard', event => {
                if (current()) byId('clipboard').value = event.detail.text;
            });
            byId('credentials').onsubmit = event => {
                event.preventDefault();
                if (!current()) return;
                rfb.sendCredentials({username: byId('username').value, password: byId('password').value, target: byId('credential-target').value});
                byId('password').value = ''; byId('credentials').hidden = true;
                handshakeDeadline();
            };
            byId('approve-server').onclick = () => {
                if (!current()) return;
                byId('verification').hidden = true; rfb.approveServer(); handshakeDeadline();
            };
            byId('reject-server').onclick = () => { if (current()) byId('close').click(); };
            handshakeDeadline();
        } catch (_) { if (current()) fail('Viewer initialization'); }
    }
    function assess(value) {
        const runtime = value.runtime, guest = value.guest;
        disagreement = runtime.disagreement === true;
        if (lastObservation !== value.observed_at) {
            lastObservation = value.observed_at;
            const allowedStates = ['running', 'stopped', 'starting', 'degraded', 'unknown'];
            record('Agent runtime', allowedStates.includes(runtime.state) ? runtime.state : 'unknown', runtime.duration_ms);
            const launchStates = ['running', 'starting', 'launching', 'exited', 'failed', 'stopped', 'stopping', 'finishing'];
            if (launchStates.includes(value.recorded_agent_state)) record('Saved coding agent launch', value.recorded_agent_state + '; separate from sandbox runtime');
            if (disagreement) record('Saved runtime record', 'does not match the independently observed live runtime');
            if (['missing_or_unreadable', 'unverified'].includes(value.saved_run)) record('Saved runtime record', 'missing or unverified; no disagreement inferred');
            if (guest.tcp === 'accepted') {
                record('Guest-local :5900', 'TCP connection accepted', guest.duration_ms);
                const greeting = ['valid', 'timeout', 'invalid', 'closed', 'unknown'].includes(guest.greeting) ? guest.greeting : 'unknown';
                record('Guest-local VNC greeting', greeting, guest.duration_ms);
            } else if (guest.tcp === 'refused') record('Guest-local :5900', 'connection refused', guest.duration_ms);
            else if (guest.tcp === 'timeout') record('Guest-local :5900', 'TCP connection timed out; service cause unverified', guest.duration_ms);
            else record('Host → guest inspection', 'unavailable or unverified', guest.duration_ms);
            noGreetingCount = guest.tcp === 'accepted' && guest.greeting === 'timeout' ? noGreetingCount + 1 : 0;
        }
        if (connected && runtime.state !== 'running') {
            status(runtime.state === 'stopped' ? 'Agent runtime is stopped' : 'Viewer connected — runtime inspection unavailable',
                'The existing viewer has separate transport checks. Current agent readiness is unverified; this page does not repair agent state.');
        } else if (connected) {
            status(disagreement ? 'Desktop connected — recorded agent state differs' : 'Desktop connected',
                disagreement ? "SafeYolo's saved runtime record differs from the observed live runtime. This page does not repair it." : 'Existing viewer transport is checked without input or screen changes.');
        } else if (runtime.state === 'unknown') {
            status('Cause not yet identified', 'Runtime inspection failed. Agent state and guest service health remain unverified.');
        } else if (runtime.state === 'stopped') {
            status('Agent runtime is stopped', value.recorded_agent_state === 'running' ? 'A saved coding agent launch says running. Independent sandbox inspection reports stopped. The saved launch is not a current runtime observation.' : 'This page does not start the agent.');
        } else if (runtime.state !== 'running') {
            status('Guest transport is unavailable', 'The runtime is not ready for verified guest inspection.');
        } else if (guest.tcp === 'refused') {
            status('Desktop service has not started', 'The guest-local VNC connection was refused. This page will check again.');
        } else if (guest.tcp === 'timeout') {
            status('Cause not yet identified', 'The guest-local VNC connection timed out. A timeout does not prove a stuck service. SafeYolo will check again.');
        } else if (noGreetingCount >= 2) {
            status('Desktop server is not responding', 'Repeated guest-local checks accepted TCP but received no VNC greeting. The service appears stuck. Ask your agent to restart x11vnc.');
        } else if (guest.tcp === 'accepted' && guest.greeting !== 'valid') {
            status('Desktop server has not sent a valid greeting', 'A bounded guest-local check failed. SafeYolo will check again before it identifies a cause.');
        } else if (guest.greeting !== 'valid') {
            status('Cause not yet identified', 'The host could not verify a guest-local VNC result. A transport timeout does not prove a stuck service.');
        } else if (!connecting) {
            status(disagreement ? "SafeYolo's recorded agent state differs" : 'Desktop service replied — checking viewer',
                failedStage ? `Last failing stage: ${failedStage}. ${failures >= 8 ? 'Automatic attempts are paused. Use Check again.' : 'The viewer will retry after backoff.'}` : 'A VNC greeting does not prove that the viewer or screen works.');
        }
        if (runtime.state === 'running' && ['exited', 'failed', 'stopped'].includes(value.recorded_agent_state)) {
            byId('explanation').textContent += ' The saved coding agent launch is not running. Its sandbox runtime is independently observed running; desktop access does not depend on that launch state.';
        }
        // Failed inspection is unknown. Let the bounded viewer attempt supply
        // evidence when the runtime is verified but the guest check failed.
        return runtime.state === 'running' && (guest.greeting === 'valid' || guest.tcp === 'unknown');
    }
    async function check() {
        if (busy) { queued = true; return; }
        if (closed || terminal || !pageActive) return;
        busy = true; queued = false;
        controller = new AbortController();
        const signal = controller.signal;
        const began = Date.now();
        let originReplied = false;
        if (began - lastTick > 30000) {
            noGreetingCount = 0;
            record('Page resume', 'long execution gap; requesting fresh observations');
        }
        lastTick = began;
        try {
            const value = await get('diagnostics', signal);
            if (!value || signal.aborted || closed || terminal) return;
            originReplied = true;
            const ready = assess(value);
            if (connected && viewerId) {
                const health = await get('session?' + viewerId, signal, 5000);
                if (health && !signal.aborted) {
                    if (health.state !== 'open' || (health.age_ms > 20000 &&
                        (health.browser_pong_age_ms === null || health.relay_pong_age_ms === null ||
                         health.browser_pong_age_ms > 20000 || health.relay_pong_age_ms > 20000))) {
                        fail('Existing viewer Ping/Pong');
                    } else record('Existing viewer transport', 'browser and guest WebSocket Ping/Pong checks active; VNC stream, rendering and application health are unverified');
                }
            }
            if (ready && !signal.aborted) await connect(signal);
        } catch (error) {
            if (!signal.aborted && !terminal && !closed) {
                noGreetingCount = 0;
                const replied = originReplied || error.originReplied;
                record('Browser → SafeYolo', replied ? 'origin replied; current diagnostic result unavailable' : 'request failed or timed out; server observations stale');
                byId('contact').textContent = lastContact ? `Server observations are stale. Last contact: ${new Date(lastContact).toLocaleTimeString()}.` : 'Server observations are unavailable.';
                status(replied ? 'SafeYolo diagnostics are unavailable' : navigator.onLine ? 'Cannot reach SafeYolo' : 'Your browser appears offline',
                    replied ? 'The intended endpoint replied. A current observation is unavailable; the page will check again.' : 'The intended diagnostic endpoint did not reply. Browser connectivity hints do not establish the cause.');
            }
        } finally {
            busy = false; controller = null;
            clearTimeout(timer);
            if (!closed && !terminal && pageActive) timer = setTimeout(check, queued ? 250 : 5000);
        }
    }
    function wake() {
        if (closed || terminal || !pageActive) return;
        clearTimeout(timer);
        if (busy) { queued = true; controller?.abort(); }
        else timer = setTimeout(check, 100);
    }
    for (const event of ['online', 'offline']) window.addEventListener(event, () => {
        noGreetingCount = 0;
        record('Browser connectivity hint', navigator.onLine ? 'online; actual origin check required' : 'offline; actual origin check required');
        wake();
    });
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') { record('Visible page', 'fresh checks requested'); wake(); }
    });
    window.addEventListener('pagehide', () => {
        pageActive = false; noGreetingCount = 0; controller?.abort(); clearTimeout(timer); dispose();
    });
    window.addEventListener('pageshow', event => {
        pageActive = true;
        if (event.persisted) { record('Page restored', 'fresh checks requested'); wake(); }
    });
    byId('close').onclick = () => {
        closed = true; controller?.abort(); clearTimeout(timer); dispose();
        status('Viewer closed', 'Automatic connection attempts have stopped. Use Check again to reconnect.');
        record('Viewer', 'closed by user; retries stopped');
    };
    byId('retry').onclick = () => {
        if (terminal) return;
        closed = false; failures = 0; retryAt = 0; failedStage = null;
        record('Retry', 'user requested fresh checks'); wake();
    };
    for (const id of ['scale', 'resize', 'viewonly', 'drag']) byId(id).onchange = settings;
    byId('fullscreen').onclick = () => { byId('screen').requestFullscreen()?.catch(() => record('Full screen', 'browser refused request')); };
    byId('ctrlaltdelete').onclick = () => rfb?.sendCtrlAltDel();
    byId('escape').onclick = () => rfb?.sendKey(0xff1b, 'Escape');
    byId('tab').onclick = () => rfb?.sendKey(0xff09, 'Tab');
    for (const [id, keysym, code] of [['ctrl', 0xffe3, 'ControlLeft'], ['alt', 0xffe9, 'AltLeft'], ['super', 0xffeb, 'MetaLeft']]) {
        byId(id).onclick = () => {
            if (!connected) return;
            const down = byId(id).getAttribute('aria-pressed') !== 'true';
            byId(id).setAttribute('aria-pressed', String(down));
            rfb.sendKey(keysym, code, down);
            rfb.focus();
        };
    }
    byId('send-clipboard').onclick = () => rfb?.clipboardPasteFrom(byId('clipboard').value);
    byId('copy').onclick = async () => {
        const text = 'SafeYolo desktop diagnostics\n' + log.join('\n');
        try {
            await navigator.clipboard.writeText(text);
            byId('copy-result').textContent = ' Diagnostics copied.';
        } catch (_) {
            // Clipboard APIs can be unavailable on an HTTP Tailnet origin.
            const field = document.createElement('textarea'); field.value = text;
            document.body.append(field); field.select();
            const copied = document.execCommand('copy'); field.remove();
            byId('copy-result').textContent = copied ? ' Diagnostics copied.' : ' Select and copy the diagnostic text below.';
        }
    };
    record('Page', 'persistent desktop page opened; no service or agent restart');
    check();
})();
