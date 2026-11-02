"""One real MCP tool held by the proof driver's FIFO; never a model substitute."""

import json
import os
import sys


def main():
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "attention-boundary-proof", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "attention_boundary", "description": "Call once for WAIT_BOUNDARY; wait for the proof controller to release the tool.",
                                 "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]}
        elif method == "tools/call":
            assert request["params"]["name"] == "attention_boundary"
            descriptor = os.open(sys.argv[1], os.O_RDONLY)
            try:
                os.read(descriptor, 1)
            finally:
                os.close(descriptor)
            result = {"content": [{"type": "text", "text": "attention boundary released"}]}
        elif method == "ping":
            result = {}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "Method not found"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
