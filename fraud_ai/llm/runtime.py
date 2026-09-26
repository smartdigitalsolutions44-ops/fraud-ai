"""Local LLM runtimes behind one interface (no provider is hard-coded).

``LocalLLMClient`` has three methods: ``health()``, ``list_models()`` and ``model_info()``,
plus ``generate(request)``. The implementations:

| runtime | talks to |
|---|---|
| ``ollama`` | an Ollama server (default ``http://localhost:11434``), ``/api/chat`` |
| ``llamacpp-server`` | a llama.cpp server (default ``http://127.0.0.1:8080``), OpenAI API |
| ``llamacpp-process`` | a local llama.cpp binary run as a subprocess with a local GGUF model |
| ``reference`` | a deterministic template analyst - **not an LLM**; an offline baseline |

**Offline by design:**

* Endpoints must be localhost, loopback or private addresses (``ensure_local_endpoint``).
  A public endpoint is refused.
* HTTP goes through an opener with **no proxy handler**, so a configured corporate or
  sandbox proxy can never route an evidence packet off the machine.
* Nothing is downloaded. There is no telemetry and no internet dependency.

Deterministic mode is the default: temperature 0, top_p 1 and a fixed seed.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from fraud_ai.core.exceptions import FraudAIError

RUNTIMES = ("ollama", "llamacpp-server", "llamacpp-process", "reference")
DEFAULT_ENDPOINTS = {"ollama": "http://localhost:11434", "llamacpp-server": "http://127.0.0.1:8080"}


class LLMRuntimeError(FraudAIError):
    kind = "runtime_unavailable"


class RuntimeUnavailableError(LLMRuntimeError):
    kind = "runtime_unavailable"


class ModelUnavailableError(LLMRuntimeError):
    kind = "model_unavailable"


class GenerationTimeoutError(LLMRuntimeError):
    kind = "timeout"


def ensure_local_endpoint(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMRuntimeError(f"LLM endpoint must be an http(s) URL, got {url!r}")
    host = parsed.hostname
    if host == "localhost":
        return url
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise LLMRuntimeError(
            "LLM endpoint must be localhost or a loopback/private IP address"
        ) from None
    if not (addr.is_loopback or addr.is_private):
        raise LLMRuntimeError("LLM endpoint must not be a public address (offline only)")
    return url


@dataclass(frozen=True)
class GenerationRequest:
    system: str
    user: str
    temperature: float = 0.0
    top_p: float = 1.0
    seed: int = 0
    max_tokens: int = 1200
    context_window: int = 8192
    json_mode: bool = True

    def parameters(self) -> dict[str, Any]:
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "seed": self.seed,
            "max_tokens": self.max_tokens,
            "context_window": self.context_window,
            "json_mode": self.json_mode,
        }


@dataclass(frozen=True)
class GenerationResult:
    text: str
    runtime: str
    model: str
    latency_seconds: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(frozen=True)
class RuntimeHealth:
    runtime: str
    available: bool
    detail: str
    version: str | None = None


@dataclass(frozen=True)
class ModelInfo:
    runtime: str
    model: str
    version: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class LocalLLMClient(Protocol):
    runtime: str
    model: str

    def health(self) -> RuntimeHealth: ...

    def list_models(self) -> list[str]: ...

    def model_info(self) -> ModelInfo: ...

    def generate(self, request: GenerationRequest) -> GenerationResult: ...


# ---------------------------------------------------------------------- HTTP (no proxy)
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http(url: str, payload: dict[str, Any] | None, timeout: float) -> Any:
    ensure_local_endpoint(url)  # http(s) to a local host only
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        data=data,
        method="GET" if data is None else "POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ModelUnavailableError(f"{url}: not found (model or endpoint missing)") from None
        raise RuntimeUnavailableError(f"{url}: HTTP {exc.code}") from None
    except TimeoutError:
        raise GenerationTimeoutError(f"{url}: no response within {timeout}s") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise GenerationTimeoutError(f"{url}: no response within {timeout}s") from None
        raise RuntimeUnavailableError(f"{url}: {exc.reason}") from None
    except json.JSONDecodeError:
        raise RuntimeUnavailableError(f"{url}: response was not JSON") from None


class OllamaClient:
    runtime = "ollama"

    def __init__(self, model: str, endpoint: str | None = None, timeout: float = 60.0) -> None:
        self.model = model
        self.endpoint = ensure_local_endpoint(endpoint or DEFAULT_ENDPOINTS["ollama"]).rstrip("/")
        self.timeout = timeout

    def health(self) -> RuntimeHealth:
        try:
            data = _http(f"{self.endpoint}/api/version", None, min(self.timeout, 5.0))
        except LLMRuntimeError as exc:
            return RuntimeHealth(self.runtime, False, str(exc))
        return RuntimeHealth(self.runtime, True, "reachable", (data or {}).get("version"))

    def list_models(self) -> list[str]:
        data = _http(f"{self.endpoint}/api/tags", None, self.timeout)
        return sorted(m.get("name", "") for m in (data or {}).get("models", []))

    def model_info(self) -> ModelInfo:
        data = _http(f"{self.endpoint}/api/show", {"model": self.model}, self.timeout) or {}
        details = data.get("details", {}) or {}
        return ModelInfo(
            self.runtime,
            self.model,
            data.get("modified_at"),
            {
                k: details.get(k)
                for k in ("family", "parameter_size", "quantization_level", "format")
            },
        )

    def generate(self, request: GenerationRequest) -> GenerationResult:
        started = time.perf_counter()
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "options": {
                "temperature": request.temperature,
                "top_p": request.top_p,
                "seed": request.seed,
                "num_ctx": request.context_window,
                "num_predict": request.max_tokens,
            },
        }
        if request.json_mode:
            payload["format"] = "json"
        data = _http(f"{self.endpoint}/api/chat", payload, self.timeout) or {}
        text = ((data.get("message") or {}).get("content")) or ""
        return GenerationResult(
            text,
            self.runtime,
            self.model,
            time.perf_counter() - started,
            data.get("prompt_eval_count"),
            data.get("eval_count"),
        )


class LlamaCppServerClient:
    runtime = "llamacpp-server"

    def __init__(self, model: str, endpoint: str | None = None, timeout: float = 60.0) -> None:
        self.model = model
        self.endpoint = ensure_local_endpoint(
            endpoint or DEFAULT_ENDPOINTS["llamacpp-server"]
        ).rstrip("/")
        self.timeout = timeout

    def health(self) -> RuntimeHealth:
        try:
            data = _http(f"{self.endpoint}/health", None, min(self.timeout, 5.0))
        except LLMRuntimeError as exc:
            return RuntimeHealth(self.runtime, False, str(exc))
        status = (data or {}).get("status", "unknown")
        return RuntimeHealth(self.runtime, status == "ok", f"status {status}")

    def list_models(self) -> list[str]:
        data = _http(f"{self.endpoint}/v1/models", None, self.timeout)
        return sorted(m.get("id", "") for m in (data or {}).get("data", []))

    def model_info(self) -> ModelInfo:
        data = _http(f"{self.endpoint}/props", None, self.timeout) or {}
        settings = data.get("default_generation_settings", {}) or {}
        return ModelInfo(
            self.runtime,
            self.model,
            data.get("build_info"),
            {"n_ctx": settings.get("n_ctx"), "model": settings.get("model")},
        )

    def generate(self, request: GenerationRequest) -> GenerationResult:
        started = time.perf_counter()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "temperature": request.temperature,
            "top_p": request.top_p,
            "seed": request.seed,
            "max_tokens": request.max_tokens,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = _http(f"{self.endpoint}/v1/chat/completions", payload, self.timeout) or {}
        choices = data.get("choices") or [{}]
        text = ((choices[0].get("message") or {}).get("content")) or ""
        usage = data.get("usage") or {}
        return GenerationResult(
            text,
            self.runtime,
            self.model,
            time.perf_counter() - started,
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
        )


class LlamaCppProcessClient:
    """Runs a local llama.cpp binary (e.g. ``llama-cli``) on a local GGUF model file."""

    runtime = "llamacpp-process"

    def __init__(
        self, model_path: str | Path, binary: str = "llama-cli", timeout: float = 120.0
    ) -> None:
        self.model_path = Path(model_path)
        self.model = self.model_path.name
        self.binary = binary
        self.timeout = timeout

    def _binary(self) -> str | None:
        return shutil.which(self.binary) or (self.binary if Path(self.binary).is_file() else None)

    def health(self) -> RuntimeHealth:
        if self._binary() is None:
            return RuntimeHealth(self.runtime, False, f"binary {self.binary!r} not found")
        if not self.model_path.is_file():
            return RuntimeHealth(self.runtime, False, f"model file {self.model_path} not found")
        return RuntimeHealth(self.runtime, True, "binary and model file present")

    def list_models(self) -> list[str]:
        return [self.model] if self.model_path.is_file() else []

    def model_info(self) -> ModelInfo:
        size = self.model_path.stat().st_size if self.model_path.is_file() else None
        return ModelInfo(self.runtime, self.model, None, {"file_bytes": size})

    def generate(self, request: GenerationRequest) -> GenerationResult:
        binary = self._binary()
        if binary is None:
            raise RuntimeUnavailableError(f"llama.cpp binary {self.binary!r} not found")
        if not self.model_path.is_file():
            raise ModelUnavailableError(f"model file {self.model_path} not found")
        prompt = f"{request.system}\n\n{request.user}\n"
        command = [
            binary,
            "-m",
            str(self.model_path),
            "--temp",
            str(request.temperature),
            "--top-p",
            str(request.top_p),
            "--seed",
            str(request.seed),
            "-n",
            str(request.max_tokens),
            "-c",
            str(request.context_window),
            "--no-display-prompt",
            "-no-cnv",  # one-shot completion, not interactive chat
            "-p",
            prompt,
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise GenerationTimeoutError(
                f"llama.cpp did not finish within {self.timeout}s"
            ) from None
        if completed.returncode != 0:
            raise RuntimeUnavailableError(
                f"llama.cpp exited with {completed.returncode}: {completed.stderr[-200:]}"
            )
        return GenerationResult(
            completed.stdout.strip(), self.runtime, self.model, time.perf_counter() - started
        )


def make_client(
    runtime: str,
    *,
    model: str | None,
    endpoint: str | None = None,
    timeout: float = 60.0,
    binary: str | None = None,
    model_path: str | None = None,
) -> LocalLLMClient:
    if runtime == "ollama":
        if not model:
            raise LLMRuntimeError("LOCAL_LLM_MODEL is required for the ollama runtime")
        return OllamaClient(model, endpoint, timeout)
    if runtime == "llamacpp-server":
        return LlamaCppServerClient(model or "local", endpoint, timeout)
    if runtime == "llamacpp-process":
        if not model_path:
            raise LLMRuntimeError("LOCAL_LLM_MODEL_PATH is required for llamacpp-process")
        return LlamaCppProcessClient(model_path, binary or "llama-cli", timeout)
    if runtime == "reference":
        from fraud_ai.llm.reference import ReferenceAnalyst

        return ReferenceAnalyst()
    raise LLMRuntimeError(f"unknown LLM runtime {runtime!r}; choose one of {RUNTIMES}")
