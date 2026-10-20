"""Run PoC1 with a fresh confined SSH connection for every control operation."""

import argparse
import json
import shlex
import subprocess
from pathlib import PurePosixPath


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--remote-probe", required=True)
    parser.add_argument("--root", required=True, help="new owned parent on the remote Mac")
    parser.add_argument("--inputs", required=True, help="native safeyolo and safeyolo-proxy directory on that Mac")
    parser.add_argument("--port", type=int, default=46375)
    args = parser.parse_args()
    ssh = ["ssh", "-F", args.ssh_config, "-o", "ControlMaster=no", "-o", "ControlPath=none", args.ssh_host]

    def shell(arguments):
        return subprocess.run([*ssh, shlex.join(arguments)], check=True, capture_output=True,
                              text=True, timeout=20).stdout

    def probe(operation, root, *arguments):
        value = json.loads(shell(["python3", "-I", "-B", args.remote_probe, operation, root, *map(str, arguments)]))
        print(json.dumps({"case": root.rsplit("/", 1)[-1], "operation": operation, "result": value}), flush=True)
        return value

    shell(["mkdir", args.root])
    normal, replacement, held, invalid = [args.root + "/" + name for name in ("normal", "replacement", "held", "invalid")]
    running = []
    try:
        assert probe("launch", normal, "--inputs", args.inputs, "--port", args.port)["returncode"] == 0
        running.append(normal)
        original = probe("status", normal)
        assert original["alive"] and original["ready"] and original["native_record"]
        assert probe("native-stop", normal)["returncode"] == 0
        assert not probe("status", normal)["alive"]
        probe("clean", normal)
        running.remove(normal)

        assert probe("launch", replacement, "--inputs", args.inputs, "--port", args.port)["returncode"] == 0
        running.append(replacement)
        current = probe("status", replacement)
        assert current["alive"] and current["ready"] and current["identity"] != original["identity"]
        assert probe("native-stop", replacement, "--identity", normal + "/data/proxy-process.json")["returncode"] == 0
        assert probe("status", replacement) == current
        # Model PID reuse with a wrong birth for the live replacement PID too.
        script = "import json,sys; p=sys.argv[1]; v=json.load(open(p+'/data/proxy-process.json')); v['token']='wrong-birth'; open(p+'/wrong.json','w').write(json.dumps(v))"
        shell(["python3", "-I", "-B", "-c", script, replacement])
        assert probe("native-stop", replacement, "--identity", replacement + "/wrong.json")["returncode"] == 0
        assert probe("status", replacement) == current
        assert probe("native-stop", replacement)["returncode"] == 0
        probe("clean", replacement)
        running.remove(replacement)

        probe("launch", held, "--inputs", args.inputs, "--port", args.port, "--hold")
        running.append(held)
        # Admin binds before Runtime loads policy. This observes startup in
        # the real proxy after signal registration, without readiness yet.
        script = "import socket,sys,time; end=time.monotonic()+5\nwhile True:\n try: c=socket.create_connection(('127.0.0.1',int(sys.argv[1])),.1); c.close(); break\n except ConnectionRefusedError:\n  assert time.monotonic()<end; time.sleep(.02)"
        shell(["python3", "-I", "-B", "-c", script, str(args.port)])
        pending = probe("status", held)
        assert pending["alive"] and not pending["ready"] and not pending["native_record"]
        stopped = probe("native-stop", held)
        after_stop = probe("status", held)
        startup_stopped = not after_stop["alive"]
        print(json.dumps({"pre_readiness_stop_pass": startup_stopped, "native_result": stopped}), flush=True)
        probe("clean", held)
        running.remove(held)

        failed = probe("launch", invalid, "--inputs", args.inputs, "--port", args.port, "--invalid")
        assert failed["returncode"] != 0
        script = "import sys; from pathlib import Path; s=(Path(sys.argv[1])/'logs/proxy.log').read_text(); assert 'Error:' in s; print(s)"
        print(shell(["python3", "-I", "-B", "-c", script, invalid]), flush=True)
        probe("clean", invalid)
        inspection = str(PurePosixPath(args.remote_probe).with_name("macos_process_argv.py"))
        print(shell(["python3", "-I", "-B", inspection, "--owned-roots", "502", args.root]), flush=True)
        if not startup_stopped:
            raise SystemExit("FAIL PoC1: native stop reported stopped while the direct held-launch proxy remained alive before readiness; fixture cleanup passed")
        print("PASS PoC1")
    finally:
        for root in running:
            probe("clean", root)


if __name__ == "__main__":
    main()
