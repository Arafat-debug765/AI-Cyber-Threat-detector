"""Model files are unpickled, so they must be proven to be ours before loading."""
import joblib
import pytest

from threat_detector import model as model_service
from threat_detector.integrity import (
    DIGEST_CHARS,
    IntegrityError,
    dump_signed,
    load_signed,
    signing_key,
)


def test_signed_model_round_trips(config, dataset):
    model_service.train(config)
    assert model_service.load_model(config) is not None


def test_saved_file_carries_its_signature(config, dataset):
    model_service.train(config)
    raw = config.model_file.read_bytes()
    assert len(raw) > DIGEST_CHARS
    assert raw[DIGEST_CHARS] == ord("\n")
    # No separate .sig file to fall out of step with the model.
    assert not config.model_file.with_suffix(".pkl.sig").exists()


def test_tampered_model_is_refused(config, dataset):
    """The attack this exists to stop: swapping in someone else's pickle."""
    model_service.train(config)
    hostile = config.model_file.parent / "hostile.pkl"
    joblib.dump({"not": "a model"}, hostile)
    signed = config.model_file.read_bytes()
    config.model_file.write_bytes(signed[: DIGEST_CHARS + 1] + hostile.read_bytes())

    with pytest.raises(IntegrityError, match="does not match"):
        model_service.load_model(config)


def test_unsigned_file_is_refused(config, dataset):
    """A bare joblib file — what an older version wrote, or another program."""
    model_service.train(config)
    joblib.dump({"version": 2}, config.model_file)

    with pytest.raises(IntegrityError, match="not in the signed format"):
        model_service.load_model(config)


def test_truncated_file_is_refused(config, dataset):
    model_service.train(config)
    config.model_file.write_bytes(config.model_file.read_bytes()[:20])

    with pytest.raises(IntegrityError):
        model_service.load_model(config)


def test_signature_from_a_different_key_is_refused(config, dataset, monkeypatch):
    model_service.train(config)
    monkeypatch.setenv("MODEL_SIGNING_KEY", "an-attacker-controlled-key")

    with pytest.raises(IntegrityError):
        model_service.load_model(config)


def test_interrupted_training_leaves_the_old_model_intact(config, dataset, monkeypatch):
    """A crash mid-train must not brick the instance.

    The previous design wrote the model and its signature as two files, so an
    interrupted write left a new model against an old signature and every
    subsequent load failed until a full retrain.
    """
    model_service.train(config)
    good = config.model_file.read_bytes()

    def explode(*_args, **_kwargs):
        raise KeyboardInterrupt("simulated crash during training")

    monkeypatch.setattr(model_service, "dump_signed", explode)
    with pytest.raises(KeyboardInterrupt):
        model_service.train(config)

    assert config.model_file.read_bytes() == good
    assert model_service.load_model(config) is not None


def test_no_temp_files_are_left_behind(config, dataset):
    model_service.train(config)
    leftovers = list(config.model_file.parent.glob(".*tmp*"))
    assert leftovers == []


def test_key_lives_outside_the_model_directory(config, dataset):
    """Anything able to write the model should not also be handed the key."""
    model_service.train(config)
    assert config.key_file.exists()
    assert config.key_file.parent != config.model_file.parent
    assert oct(config.key_file.stat().st_mode)[-3:] == "600"


def test_legacy_key_is_adopted_not_discarded(tmp_path):
    """Upgrading must not invalidate a model an earlier version signed."""
    models = tmp_path / "models"
    models.mkdir()
    legacy = models / "model_signing.key"
    legacy.write_bytes(b"a" * 32)

    key = signing_key(tmp_path / ".secrets" / "key", models_dir=models)
    assert key == b"a" * 32


def test_env_key_wins_over_files(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_SIGNING_KEY", "from-the-secret-store")
    assert signing_key(tmp_path / "unused.key") == b"from-the-secret-store"
    assert not (tmp_path / "unused.key").exists()


def test_dump_and_load_signed_directly(tmp_path):
    target = tmp_path / "thing.pkl"
    dump_signed({"hello": "world"}, target, b"key")
    assert load_signed(target, b"key") == {"hello": "world"}


def test_api_reports_tampering(client, dataset):
    client.post("/api/train")
    config = client.application.config["APP_CONFIG"]
    config.model_file.write_bytes(b"clearly not a signed model")

    response = client.get("/api/anomalies")
    assert response.status_code == 409
    assert "model" in response.get_json()["error"].lower()
