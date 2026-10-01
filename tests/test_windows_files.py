"""The Windows-only file branches (Stage 14), exercised on Linux by forcing ``IS_WINDOWS``.

The POSIX path must be untouched: the same inputs are also checked with the flag off.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from fraud_ai.models.artifact_io import ArtifactBytes, ArtifactDigestError, ArtifactReadError
from fraud_ai.trust import keys as tk
from fraud_ai.utils import winfs


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(winfs, "IS_WINDOWS", True)


def _artefact(tmp_path: Path) -> Path:
    directory = tmp_path / "model"
    directory.mkdir()
    (directory / "model.joblib").write_bytes(b"weights" * 100)
    (directory / "metadata.json").write_text('{"name": "m"}')
    return directory


def _digest(directory: Path, names: tuple[str, ...]) -> str:
    lines = "".join(
        f"{n}:{hashlib.sha256((directory / n).read_bytes()).hexdigest()}\n" for n in names
    )
    return hashlib.sha256(lines.encode()).hexdigest()


@pytest.mark.parametrize("forced", [True, False])
def test_artefact_reads_identically_on_both_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forced: bool
) -> None:
    if not forced and os.name == "nt":
        pytest.skip("the POSIX branch cannot run on Windows (that is why the branch exists)")
    monkeypatch.setattr(winfs, "IS_WINDOWS", forced)
    directory = _artefact(tmp_path)
    names = ("metadata.json", "model.joblib")
    read = ArtifactBytes.read(directory)
    assert read.files == {n: (directory / n).read_bytes() for n in names}
    read.verify(names, _digest(directory, names))
    with pytest.raises(ArtifactDigestError):
        read.verify(names, "0" * 64)


@pytest.mark.usefixtures("windows")
def test_windows_artefact_refuses_symlinked_file(tmp_path: Path) -> None:
    directory = _artefact(tmp_path)
    (tmp_path / "elsewhere").write_bytes(b"x")
    os.symlink(tmp_path / "elsewhere", directory / "extra.bin")
    with pytest.raises(ArtifactReadError, match="symlink"):
        ArtifactBytes.read(directory)


@pytest.mark.usefixtures("windows")
def test_windows_artefact_refuses_symlinked_directory(tmp_path: Path) -> None:
    directory = _artefact(tmp_path)
    link = tmp_path / "link"
    os.symlink(directory, link)
    with pytest.raises(ArtifactReadError, match="symlink"):
        ArtifactBytes.read(link)


@pytest.mark.usefixtures("windows")
def test_windows_artefact_refuses_hard_links_and_subdirectories(tmp_path: Path) -> None:
    directory = _artefact(tmp_path)
    os.link(directory / "model.joblib", tmp_path / "second-name")
    with pytest.raises(ArtifactReadError, match="hard links"):
        ArtifactBytes.read(directory)
    os.unlink(tmp_path / "second-name")
    (directory / "nested").mkdir()
    with pytest.raises(ArtifactReadError, match="not a regular file"):
        ArtifactBytes.read(directory)


@pytest.mark.usefixtures("windows")
def test_windows_artefact_enforces_the_size_limit(tmp_path: Path) -> None:
    directory = _artefact(tmp_path)
    with pytest.raises(ArtifactReadError, match="exceeds"):
        ArtifactBytes.read(directory, limit=100)


@pytest.mark.usefixtures("windows")
def test_windows_artefact_detects_a_file_changed_during_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _artefact(tmp_path)
    real = winfs.unchanged_since
    target = directory / "model.joblib"

    def grow_then_check(path: Path, info: os.stat_result) -> bool:
        if path == target:
            with open(path, "ab") as handle:
                handle.write(b"tampered")
        return real(path, info)

    monkeypatch.setattr(winfs, "unchanged_since", grow_then_check)
    with pytest.raises(ArtifactReadError, match="changed while being read"):
        ArtifactBytes.read(directory)


def test_windows_open_refuses_a_file_swapped_after_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"original")
    real_lstat = os.lstat

    def lstat_then_swap(p: os.PathLike[str] | str) -> os.stat_result:
        info = real_lstat(p)
        os.unlink(p)
        Path(p).write_bytes(b"replacement!")
        return info

    monkeypatch.setattr(winfs.os, "lstat", lstat_then_swap)
    with pytest.raises(winfs.UnsafeFileError, match="changed between"):
        winfs.open_checked(path)


def test_windows_key_loads_without_the_permission_bit_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "model.pem"
    pair = tk.generate()
    tk.write_private_key(pair, path)
    os.chmod(path, 0o644)  # what Windows Python reports for an ordinary file
    if os.name != "nt":
        with pytest.raises(tk.TrustError, match="chmod 600"):
            tk.load_private_key(path)  # POSIX: unchanged, still refused
    monkeypatch.setattr(winfs, "IS_WINDOWS", True)
    assert tk.load_private_key(path).key_id == pair.key_id


@pytest.mark.usefixtures("windows")
def test_windows_key_keeps_link_size_and_format_checks(tmp_path: Path) -> None:
    real = tmp_path / "real.pem"
    tk.write_private_key(tk.generate(), real)
    os.symlink(real, tmp_path / "link.pem")
    with pytest.raises(tk.TrustError, match="symlink"):
        tk.load_private_key(tmp_path / "link.pem")
    os.link(real, tmp_path / "hard.pem")
    with pytest.raises(tk.TrustError, match="hard links"):
        tk.load_private_key(real)
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * (tk.MAX_KEY_FILE_BYTES + 1))
    with pytest.raises(tk.TrustError, match="too large"):
        tk.load_private_key(big)
    junk = tmp_path / "junk.pem"
    junk.write_text("not a key")
    with pytest.raises(tk.TrustError, match="PKCS#8"):
        tk.load_private_key(junk)
    with pytest.raises(tk.TrustError, match="cannot open"):
        tk.load_private_key(tmp_path / "missing.pem")
