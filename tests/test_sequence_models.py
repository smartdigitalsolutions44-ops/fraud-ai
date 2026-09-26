"""Stage 6 sequence models on tiny deterministic sequences (no database): GRU forward pass,
causal Transformer masking, padding invariance, hybrid fusion, training, determinism,
save/load, artefact hashes, definition compatibility, attention inspection."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import numpy as np
import pytest
import torch

from fraud_ai.models.factory import build_model, is_sequence_kind, load_model
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.sequence_models import (
    SEQUENCE_KINDS,
    SequenceConfig,
    SequenceModel,
    SequenceModelError,
    SequenceNetwork,
    causal_mask,
)
from fraud_ai.models.torch_support import HASHES_FILE, TorchArtifactIntegrityError
from fraud_ai.sequences.definition import CATEGORICAL_FEATURES, SequenceDefinition, vocabulary
from fraud_ai.sequences.extraction import NUMERIC_NAMES, SequenceBatch
from fraud_ai.sequences.inputs import SequenceMatrix
from tests.model_helpers import make_vectors

DEF = SequenceDefinition(max_events=8)
FAST: dict[str, Any] = {
    "hidden_size": 16,
    "heads": 2,
    "ff_size": 32,
    "max_epochs": 25,
    "patience": 8,
    "batch_size": 32,
    "fusion_hidden": 8,
    "static_hidden": 8,
    "learning_rate": 1e-2,  # tiny data: few steps per epoch
}
F = len(NUMERIC_NAMES)
FAILED = vocabulary(CATEGORICAL_FEATURES["event_type"])["LOGIN_FAILURE"]
SUCCESS = vocabulary(CATEGORICAL_FEATURES["event_type"])["LOGIN_SUCCESS"]
TXN = vocabulary(CATEGORICAL_FEATURES["event_type"])["TRANSACTION_CREATED"]


def _batch(n: int = 200, seed: int = 0) -> tuple[SequenceBatch, list[int]]:
    """Fraud rows (every 5th) have several failed logins days before a normal-looking
    purchase; legitimate rows have successful logins. The target event looks the same."""
    rng = np.random.default_rng(seed)
    L = DEF.length
    cat = np.zeros((n, L, len(CATEGORICAL_FEATURES)), dtype=np.int64)
    num = np.zeros((n, L, F), dtype=np.float32)
    lengths = rng.integers(3, L + 1, size=n)
    labels = []
    for i in range(n):
        fraud = i % 5 == 0
        k = int(lengths[i])
        for j in range(k - 1):
            failed = (fraud and j < 3) or (not fraud and rng.random() < 0.05)
            cat[i, j, 0] = FAILED if failed else SUCCESS
            cat[i, j, 1:] = 2
            num[i, j] = rng.normal(0, 1, F)
        cat[i, k - 1, 0] = TXN
        cat[i, k - 1, 1:] = 2
        num[i, k - 1] = rng.normal(0, 1, F)
        num[i, k - 1, NUMERIC_NAMES.index("is_target")] = 1.0
        labels.append(int(fraud))
    return SequenceBatch(DEF, cat, num, lengths.astype(np.int64)), labels


def _matrix(n: int = 200, seed: int = 0) -> tuple[SequenceMatrix, list[int]]:
    batch, labels = _batch(n, seed)
    vectors, _ = make_vectors(n)
    return SequenceMatrix.attach(ModelMatrix.from_vectors(vectors), batch), labels


def _split() -> tuple[SequenceMatrix, list[int], SequenceMatrix, list[int]]:
    m, y = _matrix()
    return m.take(list(range(150))), y[:150], m.take(list(range(150, 200))), y[150:]


@pytest.fixture(scope="module", params=SEQUENCE_KINDS)
def trained(request: pytest.FixtureRequest) -> SequenceModel:
    train_m, train_y, val_m, val_y = _split()
    model = SequenceModel(request.param, hyperparameters=FAST, seed=1)
    model.train(train_m, train_y, validation=(val_m, val_y))
    return model


def _tensors(batch: SequenceBatch) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    return (
        torch.as_tensor(batch.categorical),
        torch.as_tensor(batch.numeric),
        torch.as_tensor(batch.lengths),
    )


# ------------------------------------------------------------------ networks
@pytest.mark.parametrize("kind", ["gru", "transformer"])
def test_forward_shape_and_padding_invariance(kind: str) -> None:
    torch.manual_seed(0)
    net = SequenceNetwork(kind, SequenceConfig(**{**FAST, "dropout": 0.0}), DEF.length).eval()
    batch, _ = _batch(20)
    cat, num, lengths = _tensors(batch)
    with torch.no_grad():
        out = net(cat, num, lengths)
        assert out.shape == (20,)
        # Garbage in the padded positions must not change anything.
        mask = torch.as_tensor(batch.mask())
        cat2 = torch.where(mask[..., None], cat, torch.full_like(cat, 3))
        num2 = torch.where(mask[..., None], num, torch.full_like(num, 99.0))
        assert torch.allclose(out, net(cat2, num2, lengths), atol=1e-6)


def test_gru_is_unidirectional_and_hybrid_needs_static() -> None:
    net = SequenceNetwork("gru", SequenceConfig(**FAST), DEF.length)
    assert net.gru is not None and not net.gru.bidirectional
    with pytest.raises(SequenceModelError, match="static"):
        SequenceNetwork("hybrid-gru", SequenceConfig(**FAST), DEF.length, static_dim=0)
    hybrid = SequenceNetwork("hybrid-gru", SequenceConfig(**FAST), DEF.length, static_dim=5)
    cat, num, lengths = _tensors(_batch(4)[0])
    with pytest.raises(SequenceModelError, match="static"):
        hybrid(cat, num, lengths)
    assert hybrid(cat, num, lengths, torch.zeros(4, 5)).shape == (4,)


def test_transformer_causal_mask() -> None:
    mask = causal_mask(4, torch.device("cpu"))
    assert mask.tolist() == [
        [False, True, True, True],
        [False, False, True, True],
        [False, False, False, True],
        [False, False, False, False],
    ]
    torch.manual_seed(0)
    net = SequenceNetwork(
        "transformer", SequenceConfig(**{**FAST, "dropout": 0.0}), DEF.length
    ).eval()
    batch, _ = _batch(6)
    cat, num, _ = _tensors(batch)
    full = torch.full((6,), DEF.length)
    changed = num.clone()
    changed[:, 5:] += 5.0  # alter only positions 5..end
    with torch.no_grad():
        a = net.encode_positions(net.encoder(cat, num), full)
        b = net.encode_positions(net.encoder(cat, changed), full)
    assert torch.allclose(a[:, :5], b[:, :5], atol=1e-6)  # earlier positions unaffected
    assert not torch.allclose(a[:, 5:], b[:, 5:])


# ------------------------------------------------------------------ training
def test_training_learns_temporal_signal(trained: SequenceModel) -> None:
    _, _, val_m, val_y = _split()
    summary = trained.training_summary
    assert summary["selection_metric"] == "validation PR-AUC"
    assert 1 <= summary["best_epoch"] <= summary["epochs_completed"]
    assert summary["pos_weight"] == pytest.approx(4.0)
    assert trained.evaluate(val_m, val_y).metrics["pr_auc"] > 0.8
    p = trained.predict_proba(val_m)
    assert p.shape == (50,) and np.all((p >= 0) & (p <= 1))
    assert trained.input_kind == "sequence" and trained.definition == DEF
    assert trained.algorithm.startswith("torch.")
    assert trained.parameter_count > 0


def test_training_is_deterministic() -> None:
    train_m, train_y, val_m, val_y = _split()

    def fit(seed: int) -> np.ndarray:
        m = SequenceModel("gru", hyperparameters={**FAST, "max_epochs": 3}, seed=seed)
        m.train(train_m, train_y, validation=(val_m, val_y))
        return m.predict_proba(val_m)

    assert np.array_equal(fit(4), fit(4))
    assert not np.array_equal(fit(4), fit(5))


def test_numeric_standardisation_uses_valid_training_positions(trained: SequenceModel) -> None:
    assert trained.network is not None
    mean = trained.network.encoder.numeric_mean.numpy()
    train_m, _, _, _ = _split()
    valid = train_m.sequences.mask()
    assert np.allclose(mean, train_m.sequences.numeric[valid].mean(axis=0), atol=1e-5)


def test_inputs_are_checked() -> None:
    train_m, train_y, val_m, val_y = _split()
    model = SequenceModel("gru", hyperparameters={**FAST, "max_epochs": 2})
    plain = ModelMatrix.from_vectors(make_vectors(10)[0])
    with pytest.raises(SequenceModelError, match="SequenceMatrix"):
        model.train(plain, [0, 1] * 5)
    with pytest.raises(SequenceModelError, match="length"):
        model.train(train_m, train_y[:-1])
    with pytest.raises(SequenceModelError, match="both classes"):
        model.train(train_m, [0] * 150)
    with pytest.raises(SequenceModelError, match="not trained"):
        model.predict_proba(val_m)
    model.train(train_m, train_y, validation=(val_m, val_y))
    other = SequenceBatch(
        SequenceDefinition(max_events=8, lookback_days=30),
        val_m.sequences.categorical,
        val_m.sequences.numeric,
        val_m.sequences.lengths,
    )
    with pytest.raises(SequenceModelError, match="different sequence definition"):
        model.predict_proba(SequenceMatrix.attach(val_m, other))
    for bad in (
        {"hidden_size": 15, "heads": 2},
        {"dropout": 1.0},
        {"loss": "hinge"},
        {"layers": 0},
        {"learning_rate": 0},
    ):
        with pytest.raises(SequenceModelError):
            SequenceConfig(**bad)
    with pytest.raises(SequenceModelError, match="unknown"):
        SequenceConfig.from_dict({"cells": 3})
    with pytest.raises(SequenceModelError, match="kind"):
        SequenceModel("lstm")
    with pytest.raises(SequenceModelError, match="imbalance"):
        SequenceModel("gru", imbalance="smote")


def test_holdout_and_imbalance_options() -> None:
    m, y = _matrix(160)
    model = SequenceModel("gru", hyperparameters={**FAST, "max_epochs": 2}, imbalance="oversample")
    model.train(m, y)
    assert model.training_summary["validation_source"].startswith("latest 15%")
    assert model.training_summary["pos_weight"] == 1.0


# ------------------------------------------------------------------ inspection
def test_attention_is_causal_and_sums_to_one(trained: SequenceModel) -> None:
    _, _, val_m, _ = _split()
    if trained.kind != "transformer":
        with pytest.raises(SequenceModelError, match="transformer"):
            trained.attention(val_m)
        return
    weights = trained.attention(val_m)
    lengths = val_m.sequences.lengths
    assert weights.shape == (50, DEF.length)
    assert np.allclose(weights.sum(axis=1), 1.0, atol=1e-5)
    for row, n in enumerate(lengths):
        assert np.all(weights[row, n:] == 0)  # no weight on padding / later positions


def test_channel_permutation_importance(trained: SequenceModel) -> None:
    _, _, val_m, val_y = _split()
    explanation = trained.explain(val_m, val_y, top_k=4)
    assert "permutation" in explanation["method"]
    top = [f["feature"] for f in explanation["top_features"]]
    assert len(top) == 4 and all(f.startswith("seq:") for f in top)
    if trained.kind != "hybrid-gru":  # the hybrid can also use the static features
        assert "seq:event_type" in top
    assert trained.explain()["top_features"] == []


# ------------------------------------------------------------------ persistence
def test_save_load_round_trip(trained: SequenceModel, tmp_path: Path) -> None:
    directory = tmp_path / trained.model_id
    digest = trained.save(directory)
    hashes = json.loads((directory / HASHES_FILE).read_text())
    assert hashes["artifact_sha256"] == digest
    expected = {"model.pt", "config.json"} | (
        {"preprocessing.json"} if trained.kind == "hybrid-gru" else set()
    )
    assert set(hashes["digest_covers"]) == expected
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["sequence_fingerprint"] == DEF.fingerprint()
    assert manifest["embedding_vocabulary_version"] == DEF.version
    loaded = load_model(trained.kind, directory, digest)
    _, _, val_m, _ = _split()
    assert np.array_equal(loaded.predict_proba(val_m), trained.predict_proba(val_m))
    with pytest.raises(SequenceModelError, match="refusing to overwrite"):
        trained.save(directory)
    with pytest.raises(TorchArtifactIntegrityError):
        SequenceModel.load(directory, "0" * 64)
    tampered = tmp_path / "tampered"
    shutil.copytree(directory, tampered)
    with (tampered / "model.pt").open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(TorchArtifactIntegrityError):
        SequenceModel.load(tampered, digest)
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SequenceModelError, match="missing"):
        SequenceModel.load(empty, digest)


def test_factory_knows_sequence_kinds() -> None:
    assert all(is_sequence_kind(k) for k in SEQUENCE_KINDS)
    assert not is_sequence_kind("gradient-boosting")
    model = build_model("transformer", hyperparameters=FAST)
    assert isinstance(model, SequenceModel) and model.kind == "transformer"
    untrained = SequenceModel("gru")
    for call in (
        untrained.manifest,
        lambda: untrained.save(Path("/nonexistent")),
        lambda: untrained.parameter_count,
        untrained.explain,
    ):
        with pytest.raises(SequenceModelError, match="not trained"):
            call()
