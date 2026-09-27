"""Thread-safe in-process model cache.

* **Key:** (model name, version, artefact SHA-256). A different digest is a different
  entry, never a stale hit.
* **Verified loads only.** A load goes through ``load_registered_model``, which verifies
  the artefact digest and its compatibility before anything is cached. A corrupt artefact
  is never cached.
* **Invalidation.** :meth:`bind` clears the cache whenever the deployment
  (configuration) changes, so the next event reloads and re-verifies every model.
* **One load per key.** Concurrent requests for the same model wait on a per-key lock
  instead of loading twice.

Only model objects are cached. Feature history, snapshots and sequences are always read
from the database for each event.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fraud_ai.database.models import ModelVersion
from fraud_ai.models.base import FraudModel
from fraud_ai.models.scoring import load_registered_model

CacheKey = tuple[str, str, str]


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    loads: int = 0
    load_failures: int = 0
    invalidations: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(vars(self))


class ModelCache:
    def __init__(self, loader: Callable[[ModelVersion], FraudModel] = load_registered_model):
        self._loader = loader
        self._items: dict[CacheKey, FraudModel] = {}
        self._lock = threading.Lock()
        self._key_locks: dict[CacheKey, threading.Lock] = {}
        self.generation: Any = None
        self.stats = CacheStats()

    def bind(self, generation: Any) -> None:
        """Invalidate everything when the deployment changes."""
        with self._lock:
            if generation != self.generation:
                if self._items or self.generation is not None:
                    self.stats.invalidations += 1
                self._items.clear()
                self._key_locks.clear()
                self.generation = generation

    def keys(self) -> list[CacheKey]:
        with self._lock:
            return sorted(self._items)

    def get(self, record: ModelVersion) -> tuple[FraudModel, bool]:
        """Return ``(model, was_cached)``."""
        key = (record.model_name, record.model_version, record.artifact_sha256 or "")
        with self._lock:
            model = self._items.get(key)
            if model is not None:
                self.stats.hits += 1
                return model, True
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:
                model = self._items.get(key)
                if model is not None:
                    self.stats.hits += 1
                    return model, True
                self.stats.misses += 1
            try:
                model = self._loader(record)
            except Exception:
                with self._lock:
                    self.stats.load_failures += 1
                raise
            with self._lock:
                self._items[key] = model
                self.stats.loads += 1
            return model, False
