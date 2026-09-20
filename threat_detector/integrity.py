"""Integrity protection for persisted models.

`joblib.load` unpickles, and unpickling executes arbitrary code chosen by
whoever wrote the file. For a tool whose whole job is detecting attacks, an
attacker-writable model directory being remote code execution is not an
acceptable footnote.

The mitigation is a keyed MAC. A saved model is a single file:

    <64 hex chars of HMAC-SHA256><newline><joblib payload>

and nothing is unpickled until the MAC over the payload verifies. Keeping the
signature *inside* the file is deliberate: with a separate `.sig` file there is
no way to replace both atomically, so a crash or a concurrent reader between
the two writes sees a new model against an old signature and the app refuses to
start. One file means one `os.replace`, which is atomic.

This does not make loading *foreign* models safe — nothing does. It ensures the
process only ever unpickles bytes it wrote itself.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from pathlib import Path
from typing import Any

import joblib

logger = logging.getLogger(__name__)

_KEY_ENV = "MODEL_SIGNING_KEY"
DIGEST_CHARS = 64  # hex-encoded SHA-256
_HEADER_BYTES = DIGEST_CHARS + 1  # digest + newline

# Where the key used to live. Keeping the model and the key that authenticates
# it in the same directory meant anything able to write the model could usually
# read the key too; the default moved out, and this is only read for migration.
LEGACY_KEY_FILE = "model_signing.key"


class IntegrityError(RuntimeError):
    """Raised when a model file fails signature verification."""


def signing_key(key_file: Path, models_dir: Path | None = None) -> bytes:
    """The HMAC key: from the environment, from `key_file`, or newly generated.

    A key in the environment is preferred — it can come from a real secret
    store and never touches the disk this app can write to.
    """
    from_env = os.getenv(_KEY_ENV)
    if from_env:
        return from_env.encode()

    key_file = Path(key_file)
    if key_file.exists():
        return key_file.read_bytes()

    # Adopt a pre-existing key from the old location rather than silently
    # invalidating models an earlier version produced.
    if models_dir is not None:
        legacy = Path(models_dir) / LEGACY_KEY_FILE
        if legacy.exists():
            logger.info("Adopting the signing key from its previous location %s", legacy)
            return legacy.read_bytes()

    key_file.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    # Create with owner-only permissions rather than writing then chmod-ing,
    # which would leave a window where the key is world-readable.
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("Generated a new model signing key at %s", key_file)
    return key


def _digest(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def dump_signed(obj: Any, model_file: Path, key: bytes) -> Path:
    """Serialise, sign and install a model in one atomic step.

    Written to a temporary file in the destination directory (so the rename
    stays on one filesystem) and moved into place with os.replace. A crash
    during training therefore leaves the previous good model intact instead of
    a half-written one the app would refuse to load.
    """
    model_file = Path(model_file)
    model_file.parent.mkdir(parents=True, exist_ok=True)

    scratch = model_file.with_name(f".{model_file.name}.{os.getpid()}.tmp")
    try:
        joblib.dump(obj, scratch)
        payload = scratch.read_bytes()
        signed = f"{_digest(payload, key)}\n".encode() + payload

        with open(scratch, "wb") as handle:
            handle.write(signed)
            handle.flush()
            os.fsync(handle.fileno())  # survive a power loss, not just a crash
        os.replace(scratch, model_file)
    finally:
        scratch.unlink(missing_ok=True)
    return model_file


def load_signed(model_file: Path, key: bytes) -> Any:
    """Verify the MAC, then unpickle. Never the other way round."""
    model_file = Path(model_file)
    raw = model_file.read_bytes()

    if len(raw) < _HEADER_BYTES or raw[DIGEST_CHARS] != ord("\n"):
        raise IntegrityError(
            "Model file is not in the signed format. It was written by another "
            "program or an older version of this app — retrain to replace it."
        )

    recorded = raw[:DIGEST_CHARS]
    payload = raw[_HEADER_BYTES:]
    # Compare as bytes, not decoded text: the header comes from a file an
    # attacker may control, and compare_digest raises TypeError on non-ASCII
    # str — turning a forged model into a crash instead of a clean refusal.
    # compare_digest is what stops the correct prefix leaking via timing.
    if not hmac.compare_digest(_digest(payload, key).encode("ascii"), recorded):
        raise IntegrityError(
            "Model signature does not match. The file was modified or written "
            "by something else. Refusing to unpickle it."
        )

    import io

    return joblib.load(io.BytesIO(payload))
