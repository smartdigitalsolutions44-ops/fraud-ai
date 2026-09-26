"""Stage 7 local runtimes: the Ollama and llama.cpp adapters against a fake local HTTP
server, llama.cpp process mode with a fake binary, timeouts, errors, the local-only endpoint
rule and the proxy bypass. No model and no internet are needed."""

from __future__ import annotations

import contextlib
import json
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from fraud_ai.llm.reference import ReferenceAnalyst
from fraud_ai.llm.runtime import (
    GenerationRequest,
    GenerationTimeoutError,
    LlamaCppProcessClient,
    LlamaCppServerClient,
    LLMRuntimeError,
    LocalLLMClient,
    ModelUnavailableError,
    OllamaClient,
    RuntimeUnavailableError,
    ensure_local_endpoint,
    make_client,
)

Route = Callable[[dict[str, Any] | None], tuple[int, Any]]


class FakeServer:
    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[tuple[str, dict[str, Any] | None]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                outer.requests.append((self.path, body))
                route = outer.routes.get(self.path)
                status, payload = route(body) if route else (404, {"error": "not found"})
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(raw)  # the client may have timed out

            do_GET = do_POST = _serve

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server() -> Iterator[FakeServer]:
    s = FakeServer()
    yield s
    s.close()


REQUEST = GenerationRequest(system="rules", user="data", seed=7, max_tokens=99, context_window=4096)


# ------------------------------------------------------------------ Ollama
def test_ollama_adapter(server: FakeServer) -> None:
    server.routes = {
        "/api/version": lambda b: (200, {"version": "0.5.1"}),
        "/api/tags": lambda b: (200, {"models": [{"name": "qwen2.5:7b"}, {"name": "llama3.1:8b"}]}),
        "/api/show": lambda b: (
            200,
            {"modified_at": "2026-01-01", "details": {"family": "qwen2", "parameter_size": "7B"}},
        ),
        "/api/chat": lambda b: (
            200,
            {"message": {"content": '{"ok": true}'}, "prompt_eval_count": 12, "eval_count": 5},
        ),
    }
    client = OllamaClient("qwen2.5:7b", server.url, timeout=5)
    assert isinstance(client, LocalLLMClient)
    health = client.health()
    assert health.available and health.version == "0.5.1"
    assert client.list_models() == ["llama3.1:8b", "qwen2.5:7b"]
    info = client.model_info()
    assert info.version == "2026-01-01" and info.details["family"] == "qwen2"
    assert info.to_dict()["model"] == "qwen2.5:7b"
    result = client.generate(REQUEST)
    assert result.text == '{"ok": true}' and result.runtime == "ollama"
    assert (result.prompt_tokens, result.completion_tokens) == (12, 5)
    _, body = server.requests[-1]
    assert body is not None
    assert body["format"] == "json" and body["stream"] is False
    assert body["options"] == {
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 7,
        "num_ctx": 4096,
        "num_predict": 99,
    }
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


def test_ollama_missing_model_and_server_errors(server: FakeServer) -> None:
    client = OllamaClient("absent", server.url, timeout=5)
    with pytest.raises(ModelUnavailableError) as exc:
        client.generate(REQUEST)  # 404 from /api/chat
    assert exc.value.kind == "model_unavailable"
    server.routes["/api/chat"] = lambda b: (500, {"error": "boom"})
    with pytest.raises(RuntimeUnavailableError, match="HTTP 500"):
        client.generate(REQUEST)
    server.routes["/api/chat"] = lambda b: (200, b"not json")
    with pytest.raises(RuntimeUnavailableError, match="not JSON"):
        client.generate(REQUEST)


def test_ollama_timeout(server: FakeServer) -> None:
    def slow(body: dict[str, Any] | None) -> tuple[int, Any]:
        time.sleep(1.0)
        return 200, {"message": {"content": "{}"}}

    server.routes["/api/chat"] = slow
    with pytest.raises(GenerationTimeoutError) as exc:
        OllamaClient("m", server.url, timeout=0.2).generate(REQUEST)
    assert exc.value.kind == "timeout"


def test_runtime_down() -> None:
    client = OllamaClient("m", "http://127.0.0.1:9", timeout=1)
    health = client.health()
    assert not health.available
    with pytest.raises(RuntimeUnavailableError):
        client.generate(REQUEST)
    assert not LlamaCppServerClient("m", "http://127.0.0.1:9", timeout=1).health().available


def test_proxy_settings_are_ignored(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """An evidence packet must never be routed through a proxy, even if one is configured."""
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    server.routes["/api/version"] = lambda b: (200, {"version": "x"})
    assert OllamaClient("m", server.url, timeout=5).health().available


# ------------------------------------------------------------------ llama.cpp server
def test_llamacpp_server_adapter(server: FakeServer) -> None:
    server.routes = {
        "/health": lambda b: (200, {"status": "ok"}),
        "/v1/models": lambda b: (200, {"data": [{"id": "phi-3-mini.gguf"}]}),
        "/props": lambda b: (
            200,
            {"build_info": "b4000", "default_generation_settings": {"n_ctx": 8192}},
        ),
        "/v1/chat/completions": lambda b: (
            200,
            {
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            },
        ),
    }
    client = LlamaCppServerClient("phi-3-mini", server.url, timeout=5)
    assert client.health().available
    assert client.list_models() == ["phi-3-mini.gguf"]
    assert client.model_info().version == "b4000"
    result = client.generate(REQUEST)
    assert result.text == "{}" and result.completion_tokens == 1
    _, body = server.requests[-1]
    assert body is not None
    assert body["response_format"] == {"type": "json_object"}
    assert (body["temperature"], body["seed"], body["max_tokens"]) == (0.0, 7, 99)


def test_llamacpp_server_loading_is_not_available(server: FakeServer) -> None:
    server.routes["/health"] = lambda b: (200, {"status": "loading model"})
    assert not LlamaCppServerClient("m", server.url).health().available


def test_llamacpp_server_empty_reply(server: FakeServer) -> None:
    server.routes["/v1/chat/completions"] = lambda b: (200, {})
    assert LlamaCppServerClient("m", server.url).generate(REQUEST).text == ""


# ------------------------------------------------------------------ llama.cpp process
def _fake_binary(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-llama"
    path.write_text(f"#!{sys.executable}\nimport sys, time\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_llamacpp_process_adapter(tmp_path: Path) -> None:
    binary = _fake_binary(
        tmp_path,
        "args = sys.argv[1:]\n"
        "assert args[args.index('--temp') + 1] == '0.0'\n"
        "assert args[args.index('--seed') + 1] == '7'\n"
        "assert '-no-cnv' in args\n"
        "print('  {\"echo\": %d}  ' % len(args[args.index('-p') + 1]))",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    client = LlamaCppProcessClient(model, str(binary), timeout=10)
    assert client.health().available
    assert client.list_models() == ["model.gguf"]
    assert client.model_info().details == {"file_bytes": 4}
    result = client.generate(REQUEST)
    assert json.loads(result.text) == {"echo": len("rules\n\ndata\n")}
    assert result.runtime == "llamacpp-process"


def test_llamacpp_process_failures(tmp_path: Path) -> None:
    model = tmp_path / "model.gguf"
    missing = LlamaCppProcessClient(model, "definitely-not-installed-llama")
    assert "not found" in missing.health().detail
    with pytest.raises(RuntimeUnavailableError):
        missing.generate(REQUEST)
    binary = _fake_binary(tmp_path, "sys.exit(3)")
    no_model = LlamaCppProcessClient(model, str(binary))
    assert not no_model.health().available and no_model.list_models() == []
    assert no_model.model_info().details == {"file_bytes": None}
    with pytest.raises(ModelUnavailableError):
        no_model.generate(REQUEST)
    model.write_bytes(b"GGUF")
    with pytest.raises(RuntimeUnavailableError, match="exited with 3"):
        LlamaCppProcessClient(model, str(binary)).generate(REQUEST)
    slow = _fake_binary(tmp_path, "time.sleep(5)")
    with pytest.raises(GenerationTimeoutError):
        LlamaCppProcessClient(model, str(slow), timeout=0.3).generate(REQUEST)


# ------------------------------------------------------------------ configuration rules
@pytest.mark.parametrize(
    "url",
    ["http://localhost:11434", "http://127.0.0.1:8080", "http://10.0.0.5:1", "http://[::1]:1"],
)
def test_local_endpoints_are_accepted(url: str) -> None:
    assert ensure_local_endpoint(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8:11434",
        "https://api.example.com",
        "ftp://localhost",
        "file:///etc/passwd",
        "x",
    ],
)
def test_public_or_odd_endpoints_are_refused(url: str) -> None:
    with pytest.raises(LLMRuntimeError):
        ensure_local_endpoint(url)
    with pytest.raises(LLMRuntimeError):
        OllamaClient("m", url)


def test_make_client() -> None:
    assert isinstance(make_client("reference", model=None), ReferenceAnalyst)
    assert isinstance(make_client("ollama", model="m"), OllamaClient)
    server_client = make_client("llamacpp-server", model=None)
    assert isinstance(server_client, LlamaCppServerClient) and server_client.model == "local"
    process = make_client("llamacpp-process", model=None, model_path="/x/m.gguf", binary="b")
    assert isinstance(process, LlamaCppProcessClient) and process.binary == "b"
    with pytest.raises(LLMRuntimeError, match="LOCAL_LLM_MODEL"):
        make_client("ollama", model=None)
    with pytest.raises(LLMRuntimeError, match="MODEL_PATH"):
        make_client("llamacpp-process", model=None)
    with pytest.raises(LLMRuntimeError, match="unknown LLM runtime"):
        make_client("openai", model="gpt")
    with pytest.raises(LLMRuntimeError):
        make_client("ollama", model="m", endpoint="http://8.8.8.8")


def test_generation_request_defaults_are_deterministic() -> None:
    params = GenerationRequest("s", "u").parameters()
    assert params["temperature"] == 0.0 and params["seed"] == 0 and params["top_p"] == 1.0
