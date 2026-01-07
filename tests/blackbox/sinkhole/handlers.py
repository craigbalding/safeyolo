"""Response handlers for different simulated hosts."""

from dataclasses import dataclass, field
import json

if __name__ != "__main__":
    from models import CapturedRequest


@dataclass
class Response:
    """HTTP response to return to client."""

    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.headers:
            self.headers = {"Content-Type": "application/json"}

    @classmethod
    def json_response(cls, data: dict, status: int = 200) -> "Response":
        """Create a JSON response."""
        return cls(
            status=status,
            body=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
        )


class OpenAIHandler:
    """Simulates OpenAI API responses."""

    def handle(self, request: "CapturedRequest") -> Response:
        if request.path == "/v1/chat/completions":
            return Response.json_response({
                "id": "chatcmpl-test123",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello from sinkhole!"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            })
        elif request.path == "/v1/models":
            return Response.json_response({"data": [{"id": "gpt-4", "object": "model"}]})
        return Response.json_response({"error": "not found"}, 404)


class AnthropicHandler:
    """Simulates Anthropic API responses."""

    def handle(self, request: "CapturedRequest") -> Response:
        if request.path == "/v1/messages":
            return Response.json_response({
                "id": "msg-test123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello from sinkhole!"}],
                "model": "claude-3-opus-20240229",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            })
        return Response.json_response({"error": "not found"}, 404)


class GenericHandler:
    """Returns 200 OK with request echo for any request."""

    def handle(self, request: "CapturedRequest") -> Response:
        return Response.json_response({
            "received": True,
            "host": request.host,
            "method": request.method,
            "path": request.path,
            "has_auth": "authorization" in {k.lower() for k in request.headers}
            or "x-api-key" in {k.lower() for k in request.headers},
        })


class FailingHandler:
    """Returns 500 errors to trigger circuit breaker."""

    def __init__(self, fail_count: int = 999):
        self.fail_count = fail_count
        self.request_count = 0

    def handle(self, request: "CapturedRequest") -> Response:
        self.request_count += 1
        if self.request_count <= self.fail_count:
            return Response.json_response({"error": "Internal Server Error"}, 500)
        return Response.json_response({"status": "recovered"}, 200)


# Handler registry - maps hostnames to handlers
HANDLERS: dict[str, object] = {
    "api.openai.com": OpenAIHandler(),
    "api.anthropic.com": AnthropicHandler(),
    "evil.com": GenericHandler(),
    "attacker.com": GenericHandler(),
    "httpbin.org": GenericHandler(),
    "failing.test": FailingHandler(),
}

DEFAULT_HANDLER = GenericHandler()
