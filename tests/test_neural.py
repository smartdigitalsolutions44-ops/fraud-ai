"""Stage 5 neural models on tiny deterministic data (no database): construction, forward
pass, loss, training loop, early stopping, determinism, checkpointing, hashing, loading,
compatibility, the autoencoder and anomaly scoring."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import numpy as np
import pytest
import torch

from fraud_ai.features.vector import MissingReason
from fraud_ai.models.anomaly import (
    AnomalyModelError,
    AutoencoderConfig,
    AutoencoderModel,
    build_autoencoder,
)
from fraud_ai.models.base import ANOMALY_SCORE, FRAUD_PROBABILITY
from fraud_ai.models.estimators import ModelError
from fraud_ai.models.experiments import ExperimentGrid, _rank_key
from fraud_ai.models.factory import (
    build_model,
    is_anomaly_model,
    kind_for_name,
    load_model,
    model_name,
)
from fraud_ai.models.matrix import FeatureVersionMismatchError, ModelMatrix
from fraud_ai.models.neural import (
    CONFIG_FILE,
    WEIGHTS_FILE,
    NeuralConfig,
    NeuralModelError,
    NeuralNetworkModel,
    build_network,
    fraud_loss,
    overfitting_flags,
)
from fraud_ai.models.torch_support import (
    HASHES_FILE,
    TorchArtifactIntegrityError,
    TorchModelError,
    deterministic,
    parameter_count,
    resolve_device,
)
from tests.model_helpers import make_vector, make_vectors

FAST: dict[str, Any] = {
    "hidden_sizes": [16, 8],
    "max_epochs": 12,
    "patience": 4,
    "batch_size": 32,
    "dropout": 0.1,
}


def _data(n: int = 200, fraud_every: int = 5) -> tuple[ModelMatrix, list[int]]:
    vectors, labels = make_vectors(n, fraud_every=fraud_every)
    return ModelMatrix.from_vectors(vectors), labels


def _split(n: int = 200) -> tuple[ModelMatrix, list[int], ModelMatrix, list[int]]:
    matrix, y = _data(n)
    cut = int(n * 0.75)
    return matrix.take(list(range(cut))), y[:cut], matrix.take(list(range(cut, n))), y[cut:]


@pytest.fixture(scope="module")
def trained() -> NeuralNetworkModel:
    train_m, train_y, val_m, val_y = _split()
    model = NeuralNetworkModel(hyperparameters=FAST, seed=3)
    model.train(train_m, train_y, validation=(val_m, val_y))
    return model


# ------------------------------------------------------------------ construction
def test_network_construction_and_forward_pass() -> None:
    config = NeuralConfig(hidden_sizes=(128, 64, 32))
    net = build_network(40, config)
    kinds = [type(layer).__name__ for layer in net]
    assert kinds == ["Linear", "LayerNorm", "ReLU", "Dropout"] * 3 + ["Linear"]
    assert parameter_count(net) == (40 * 128 + 128) + (128 * 64 + 64) + (64 * 32 + 32) + (
        32 + 1
    ) + 2 * (128 + 64 + 32)
    out = net(torch.zeros(7, 40))
    assert out.shape == (7, 1)
    gelu = build_network(
        5,
        NeuralConfig(hidden_sizes=(4,), activation="gelu", normalization="batchnorm", dropout=0.0),
    )
    assert [type(x).__name__ for x in gelu] == ["Linear", "BatchNorm1d", "GELU", "Linear"]
    plain = build_network(5, NeuralConfig(hidden_sizes=(4,), normalization="none"))
    assert "LayerNorm" not in [type(x).__name__ for x in plain]


@pytest.mark.parametrize(
    "bad",
    [
        {"hidden_sizes": ()},
        {"hidden_sizes": (0,)},
        {"activation": "tanh"},
        {"normalization": "group"},
        {"loss": "hinge"},
        {"dropout": 1.0},
        {"batch_size": 0},
        {"learning_rate": 0},
        {"weight_decay": -1},
        {"holdout_fraction": 0.7},
        {"input_clip": 0},
    ],
)
def test_config_validation(bad: dict[str, Any]) -> None:
    with pytest.raises(NeuralModelError):
        NeuralConfig(**bad)


def test_config_round_trip_and_unknown_keys() -> None:
    config = NeuralConfig.from_dict({"hidden_sizes": [8, 4], "dropout": 0.2})
    assert config.hidden_sizes == (8, 4)
    again = NeuralConfig.from_dict(config.to_dict())
    assert again == config and config.to_dict()["optimizer"] == "AdamW"
    with pytest.raises(NeuralModelError, match="unknown"):
        NeuralConfig.from_dict({"layers": 3})


def test_weighted_and_focal_loss() -> None:
    logits = torch.tensor([2.0, -2.0, 0.5, -0.5])
    y = torch.tensor([1.0, 0.0, 0.0, 1.0])
    one = torch.tensor(1.0)
    plain = fraud_loss(logits, y, one, NeuralConfig())
    expected = torch.nn.functional.binary_cross_entropy_with_logits(logits, y)
    assert torch.isclose(plain, expected)
    weighted = fraud_loss(logits, y, torch.tensor(10.0), NeuralConfig())
    assert weighted > plain  # misclassified positives now cost more
    focal = fraud_loss(logits, y, one, NeuralConfig(loss="focal", focal_gamma=2.0))
    assert focal < plain  # easy examples are down-weighted
    gamma0 = fraud_loss(logits, y, one, NeuralConfig(loss="focal", focal_gamma=0.0))
    assert torch.isclose(gamma0, plain)


def test_device_resolution() -> None:
    assert resolve_device("cpu").type == "cpu"
    assert resolve_device("auto").type in ("cpu", "cuda")
    with pytest.raises(TorchModelError, match="unknown device"):
        resolve_device("tpu")
    if not torch.cuda.is_available():
        with pytest.raises(TorchModelError, match="CUDA"):
            resolve_device("cuda")


# ------------------------------------------------------------------ training
def test_training_learns_and_records_history(trained: NeuralNetworkModel) -> None:
    summary = trained.training_summary
    assert summary["selection_metric"] == "validation PR-AUC"
    assert summary["validation_source"] == "validation split"
    assert 1 <= summary["best_epoch"] <= summary["epochs_completed"] <= FAST["max_epochs"]
    assert summary["pos_weight"] == pytest.approx(4.0)  # 4 legitimate rows per fraud row
    for h in trained.history:
        assert set(h) >= {
            "epoch",
            "train_loss",
            "validation_loss",
            "validation_pr_auc",
            "validation_roc_auc",
            "learning_rate",
            "train_pr_auc",
        }
    assert [h["epoch"] for h in trained.history] == list(range(1, len(trained.history) + 1))
    _, _, val_m, val_y = _split()
    result = trained.evaluate(val_m, val_y)
    assert result.metrics["pr_auc"] > 0.8  # the helper's fraud signal is learnable
    p = trained.predict_proba(val_m)
    assert p.shape == (len(val_y),) and p.dtype == np.float64
    assert np.all((p >= 0) & (p <= 1))
    assert set(np.unique(trained.predict(val_m, 0.5))) <= {0, 1}
    assert trained.score_kind == FRAUD_PROBABILITY and trained.algorithm == "torch.FeedForward"


def test_early_stopping_restores_the_best_checkpoint() -> None:
    train_m, train_y, val_m, val_y = _split()
    model = NeuralNetworkModel(hyperparameters={**FAST, "max_epochs": 40, "patience": 2})
    model.train(train_m, train_y, validation=(val_m, val_y))
    summary = model.training_summary
    best = summary["best_epoch"]
    if summary["stopped_early"]:
        assert summary["epochs_completed"] == best + 2
    # The restored network reproduces the best epoch's validation PR-AUC.
    restored = model.evaluate(val_m, val_y).metrics["pr_auc"]
    assert restored == pytest.approx(model.history[best - 1]["validation_pr_auc"], abs=1e-9)


def test_training_is_deterministic_for_a_seed() -> None:
    train_m, train_y, val_m, val_y = _split()

    def fit(seed: int) -> np.ndarray:
        m = NeuralNetworkModel(hyperparameters=FAST, seed=seed)
        m.train(train_m, train_y, validation=(val_m, val_y))
        return m.predict_proba(val_m)

    first, second = fit(11), fit(11)
    assert np.array_equal(first, second)  # bit-identical on CPU
    assert not np.array_equal(first, fit(12))


def test_single_row_prediction_matches_batch(trained: NeuralNetworkModel) -> None:
    _, _, val_m, _ = _split()
    batch = trained.predict_proba(val_m)
    singles = [trained.predict_proba(val_m.take([i]))[0] for i in range(5)]
    assert np.allclose(batch[:5], singles, atol=1e-6)


def test_holdout_is_used_without_a_validation_split() -> None:
    matrix, y = _data(200)
    model = NeuralNetworkModel(hyperparameters=FAST)
    model.train(matrix, y)
    summary = model.training_summary
    assert summary["validation_source"].startswith("latest 15%")
    assert summary["fit_rows"] + summary["validation_rows"] == 200


def test_validation_with_one_class_falls_back_to_loss() -> None:
    train_m, train_y, val_m, val_y = _split()
    legit = [i for i, v in enumerate(val_y) if v == 0]
    model = NeuralNetworkModel(hyperparameters=FAST)
    model.train(train_m, train_y, validation=(val_m.take(legit), [0] * len(legit)))
    assert model.training_summary["selection_metric"] == "validation loss"


@pytest.mark.parametrize("imbalance,weight", [("none", 1.0), ("oversample", 1.0)])
def test_imbalance_strategies(imbalance: str, weight: float) -> None:
    train_m, train_y, val_m, val_y = _split()
    model = NeuralNetworkModel(hyperparameters=FAST, imbalance=imbalance)
    model.train(train_m, train_y, validation=(val_m, val_y))
    assert model.training_summary["pos_weight"] == weight
    with pytest.raises(NeuralModelError, match="imbalance"):
        NeuralNetworkModel(imbalance="smote")


def test_batchnorm_and_focal_variants_train() -> None:
    train_m, train_y, val_m, val_y = _split()
    for extra in ({"normalization": "batchnorm", "batch_size": 7}, {"loss": "focal"}):
        model = NeuralNetworkModel(hyperparameters={**FAST, **extra, "max_epochs": 3})
        model.train(train_m, train_y, validation=(val_m, val_y))
        assert model.training_summary["epochs_completed"] >= 1


def test_training_errors() -> None:
    matrix, y = _data(40)
    model = NeuralNetworkModel(hyperparameters=FAST)
    with pytest.raises(NeuralModelError, match="length"):
        model.train(matrix, y[:-1])
    with pytest.raises(NeuralModelError, match="both classes"):
        model.train(matrix, [0] * 40)
    # The time-ordered holdout would take every fraud row: the fitting part has one class.
    with pytest.raises(NeuralModelError, match="both classes"):
        model.train(matrix, [0] * 35 + [1] * 5)
    with pytest.raises(NeuralModelError, match="not trained"):
        model.predict_proba(matrix)
    with pytest.raises(NeuralModelError, match="not trained"):
        model.explain(matrix, y)
    with pytest.raises(NeuralModelError, match="not trained"):
        model.architecture()
    with pytest.raises(NeuralModelError, match="not trained"):
        model.save(Path("/nonexistent"))


def test_overfitting_flags() -> None:
    history = [
        {"epoch": 1, "train_pr_auc": 0.995, "validation_pr_auc": 0.70, "validation_loss": 0.5},
        {"epoch": 2, "train_pr_auc": 1.0, "validation_pr_auc": 0.60, "validation_loss": 0.9},
    ]
    flags = overfitting_flags(history, 1)
    assert any("gap" in f for f in flags) and any("memorising" in f for f in flags)
    assert any("fell from" in f for f in flags) and any("rose" in f for f in flags)
    assert overfitting_flags([], 0) == []


def test_permutation_importance(trained: NeuralNetworkModel) -> None:
    _, _, val_m, val_y = _split()
    explanation = trained.explain(val_m, val_y, top_k=5)
    assert "permutation" in explanation["method"]
    top = [f["feature"] for f in explanation["top_features"]]
    assert len(top) == 5
    assert {"transaction_amount_minor_units", "network_type", "new_device"} & set(top)
    assert trained.explain()["top_features"] == []
    assert trained.explain(val_m, [0] * len(val_y))["top_features"] == []


# ------------------------------------------------------------------ persistence
def test_save_load_round_trip_and_hashes(trained: NeuralNetworkModel, tmp_path: Path) -> None:
    directory = tmp_path / "neural-network-1.0.0"
    digest = trained.save(directory)
    names = {p.name for p in directory.iterdir()}
    assert names == {
        "model.pt",
        "config.json",
        "preprocessing.json",
        "history.json",
        "manifest.json",
        HASHES_FILE,
    }
    hashes = json.loads((directory / HASHES_FILE).read_text())
    assert hashes["artifact_sha256"] == digest
    assert set(hashes["files"]) == names - {HASHES_FILE}
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["parameter_count"] == trained.parameter_count
    assert manifest["environment"]["torch"] == torch.__version__
    assert manifest["optimizer"] == "AdamW" and manifest["training"]["best_epoch"] >= 1
    loaded = NeuralNetworkModel.load(directory, digest)
    _, _, val_m, _ = _split()
    assert np.array_equal(loaded.predict_proba(val_m), trained.predict_proba(val_m))
    assert loaded.history == trained.history
    with pytest.raises(NeuralModelError, match="refusing to overwrite"):
        trained.save(directory)
    factory_loaded = load_model("neural-network", directory, digest)
    assert isinstance(factory_loaded, NeuralNetworkModel)


def test_tampered_artifacts_are_refused(trained: NeuralNetworkModel, tmp_path: Path) -> None:
    directory = tmp_path / "m"
    digest = trained.save(directory)
    with pytest.raises(TorchArtifactIntegrityError, match="digest"):
        NeuralNetworkModel.load(directory, "0" * 64)
    for name in (WEIGHTS_FILE, CONFIG_FILE):
        copy = tmp_path / f"copy-{name}"
        shutil.copytree(directory, copy)
        with (copy / name).open("ab") as fh:
            fh.write(b" ")
        with pytest.raises(TorchArtifactIntegrityError):
            NeuralNetworkModel.load(copy, digest)
    missing = tmp_path / "missing"
    shutil.copytree(directory, missing)
    (missing / WEIGHTS_FILE).unlink()
    with pytest.raises(TorchArtifactIntegrityError, match="missing"):
        NeuralNetworkModel.load(missing, digest)


def test_incompatible_inputs_are_refused(trained: NeuralNetworkModel) -> None:
    _, _, val_m, _ = _split()
    # ModelMatrix itself refuses a foreign catalogue; build one bypassing that check to prove
    # the model's own guard also refuses it.
    other = object.__new__(ModelMatrix)
    for name in ("feature_version", "feature_names", "values", "missing"):
        object.__setattr__(other, name, getattr(val_m, name))
    object.__setattr__(other, "catalogue_fingerprint", "different-catalogue")
    with pytest.raises(FeatureVersionMismatchError):
        trained.predict_proba(other)
    object.__setattr__(other, "feature_version", "fraud-features-9.9.9")
    with pytest.raises(FeatureVersionMismatchError):
        trained.predict_proba(other)


def test_missing_reasons_stay_distinct(trained: NeuralNetworkModel) -> None:
    columns = trained.preprocessor.output_columns
    reasons = {r.value for r in MissingReason}
    indicators = [c for c in columns if "__" in c and c.split("__")[1] in reasons]
    assert {c.split("__")[1] for c in indicators} <= reasons
    rows = [make_vector({"device_age_days": r}) for r in MissingReason]
    X = trained.transform(ModelMatrix.from_vectors(rows))
    assert len({tuple(x) for x in X}) == 3  # three reasons -> three distinct inputs


# ------------------------------------------------------------------ factory
def test_factory_names_and_kinds() -> None:
    assert model_name("neural-network") == "neural-network"
    assert kind_for_name("gradient-boosting") == "gradient-boosting"
    assert is_anomaly_model("autoencoder") and not is_anomaly_model("neural-network")
    assert isinstance(build_model("neural-network", hyperparameters=FAST), NeuralNetworkModel)
    assert isinstance(build_model("autoencoder"), AutoencoderModel)
    for bad in (
        lambda: model_name("svm"),
        lambda: kind_for_name("svm"),
        lambda: build_model("svm"),
        lambda: load_model("svm", Path("."), ""),
    ):
        with pytest.raises(ModelError):
            bad()


def test_experiment_grid() -> None:
    grid = ExperimentGrid()
    configs = grid.configurations()
    assert len(configs) == 3 * 3 * 2 * 2 == grid.describe()["configurations"]
    small = {"validation_pr_auc": 0.9, "parameter_count": 10, "hyperparameters": {}}
    big = {"validation_pr_auc": 0.9, "parameter_count": 99, "hyperparameters": {}}
    undefined = {"validation_pr_auc": None, "parameter_count": 1, "hyperparameters": {}}
    ranked = sorted([big, undefined, small], key=_rank_key)
    assert ranked == [small, big, undefined]


# ------------------------------------------------------------------ autoencoder
@pytest.fixture(scope="module")
def autoencoder() -> AutoencoderModel:
    train_m, train_y, val_m, val_y = _split()
    model = AutoencoderModel(
        hyperparameters={"hidden_sizes": [16], "bottleneck": 4, "max_epochs": 30, "patience": 5},
        seed=1,
    )
    model.train(train_m, train_y, validation=(val_m, val_y))
    return model


def test_autoencoder_architecture_and_reconstruction() -> None:
    config = AutoencoderConfig(hidden_sizes=(64, 32), bottleneck=8)
    net = build_autoencoder(20, config)
    linear = [layer for layer in net if isinstance(layer, torch.nn.Linear)]
    assert [(lin.in_features, lin.out_features) for lin in linear] == [
        (20, 64),
        (64, 32),
        (32, 8),
        (8, 32),
        (32, 64),
        (64, 20),
    ]
    assert net(torch.zeros(3, 20)).shape == (3, 20)
    with pytest.raises(AnomalyModelError):
        AutoencoderConfig(bottleneck=0)
    with pytest.raises(AnomalyModelError, match="unknown"):
        AutoencoderConfig.from_dict({"layers": 2})


def test_autoencoder_trains_on_legitimate_rows_only(autoencoder: AutoencoderModel) -> None:
    summary = autoencoder.training_summary
    train_y = _split()[1]
    assert summary["fraud_rows_excluded_from_fit"] == sum(train_y)
    assert summary["fit_rows"] == len(train_y) - sum(train_y)
    history = autoencoder.history
    assert history[summary["best_epoch"] - 1]["validation_loss"] == min(
        h["validation_loss"] for h in history
    )
    assert history[0]["train_loss"] > history[summary["best_epoch"] - 1]["train_loss"]


def test_anomaly_scores(autoencoder: AutoencoderModel) -> None:
    _, _, val_m, val_y = _split()
    errors = autoencoder.reconstruction_error(val_m)
    scores = autoencoder.predict_proba(val_m)
    assert np.all((scores >= 0) & (scores <= 1)) and errors.shape == scores.shape
    order = np.argsort(errors)
    assert np.all(np.diff(scores[order]) >= 0)  # monotone in reconstruction error
    y = np.asarray(val_y)
    assert scores[y == 1].mean() > scores[y == 0].mean()  # helper fraud is unusual
    assert autoencoder.score_kind == ANOMALY_SCORE
    assert autoencoder.anomaly_score(np.array([-1.0, 1e9])).tolist() == [0.0, 1.0]
    result = autoencoder.evaluate(val_m, val_y)
    assert result.threshold == 0.95 and result.notes["score"] == ANOMALY_SCORE
    explanation = autoencoder.explain(val_m, val_y, top_k=3)
    assert len(explanation["top_features"]) == 3
    assert "fraud_mean_error" in explanation["top_features"][0]
    assert autoencoder.explain()["top_features"] == []
    assert "importance" in autoencoder.explain(val_m)["top_features"][0]


def test_autoencoder_save_load(autoencoder: AutoencoderModel, tmp_path: Path) -> None:
    digest = autoencoder.save(tmp_path / "ae")
    assert (tmp_path / "ae" / "reference.json").exists()
    loaded = AutoencoderModel.load(tmp_path / "ae", digest)
    _, _, val_m, _ = _split()
    assert np.array_equal(loaded.predict_proba(val_m), autoencoder.predict_proba(val_m))
    assert loaded.manifest()["score_kind"] == ANOMALY_SCORE
    with pytest.raises(AnomalyModelError, match="refusing"):
        autoencoder.save(tmp_path / "ae")
    with pytest.raises(TorchArtifactIntegrityError):
        AutoencoderModel.load(tmp_path / "ae", "0" * 64)


def test_autoencoder_holdout_and_errors() -> None:
    matrix, y = _data(120)
    model = AutoencoderModel(
        hyperparameters={"hidden_sizes": [8], "bottleneck": 2, "max_epochs": 2}
    )
    model.train(matrix, y)
    assert model.training_summary["validation_source"] == "latest legitimate training rows"
    with pytest.raises(AnomalyModelError, match="length"):
        model.train(matrix, y[:-1])
    fresh = AutoencoderModel()
    for call in (
        lambda: fresh.predict_proba(matrix),
        lambda: fresh.manifest(),
        lambda: fresh.save(Path("/nonexistent")),
    ):
        with pytest.raises(AnomalyModelError, match="not trained"):
            call()
    with pytest.raises(AnomalyModelError, match="too few"):
        fresh.train(matrix.take([0, 1]), [1, 1])


def test_deterministic_context_restores_torch_state() -> None:
    threads = torch.get_num_threads()
    with deterministic(5):
        assert torch.get_num_threads() == 1 and torch.are_deterministic_algorithms_enabled()
    assert torch.get_num_threads() == threads
    assert not torch.are_deterministic_algorithms_enabled()
