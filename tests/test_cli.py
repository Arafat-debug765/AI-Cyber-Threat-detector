"""The command line is the primary interface; test it the way a user drives it."""
import json

import pytest

from threat_detector import cli


@pytest.fixture(autouse=True)
def never_start_a_real_server(monkeypatch):
    """No test may bind a port and block: record what serve would have run."""
    calls = {}
    monkeypatch.setattr("flask.Flask.run", lambda self, **kw: calls.update(kw))
    return calls


@pytest.fixture
def captures(tmp_path):
    """A capture with planted attacks and a clean baseline, as a user would make them."""
    attacks, baseline = tmp_path / "packets.csv", tmp_path / "baseline.csv"
    assert cli.main(["generate", "--output", str(attacks)]) == 0
    assert cli.main(["generate", "--output", str(baseline), "--no-attacks", "--seed", "7"]) == 0
    return attacks, baseline


def _flags(tmp_path, attacks, baseline):
    return ["--data", str(attacks), "--baseline", str(baseline),
            "--model", str(tmp_path / "model.pkl")]


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert "threat-detector 1." in capsys.readouterr().out


def test_generate_writes_where_it_is_told(tmp_path):
    target = tmp_path / "nested" / "out.csv"
    assert cli.main(["generate", "--output", str(target), "--count", "500"]) == 0
    assert target.exists()


def test_generate_defaults_to_the_working_directory():
    """It used to default to a path inside the installed package."""
    from pathlib import Path

    assert cli.main(["generate", "--count", "200"]) == 0
    assert (Path.cwd() / "data" / "packets.csv").exists()


def test_train_detect_inspect(tmp_path, captures, capsys):
    flags = _flags(tmp_path, *captures)
    assert cli.main([*flags, "train"]) == 0
    assert cli.main([*flags, "inspect"]) == 0
    assert "feature_set      flow" in capsys.readouterr().out

    assert cli.main([*flags, "detect", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    flagged = {row["src_ip"] for row in result["anomalies"]}
    assert {"192.168.0.66", "192.168.0.67", "192.168.0.69"} <= flagged


def test_detect_without_a_model_fails_cleanly(tmp_path, captures, capsys):
    assert cli.main([*_flags(tmp_path, *captures), "detect"]) == 1
    assert "No trained model" in capsys.readouterr().err


def test_selfcheck_passes_on_the_reference_data(tmp_path, captures):
    assert cli.main([*_flags(tmp_path, *captures), "selfcheck"]) == 0


def test_selfcheck_requires_a_baseline(tmp_path, captures):
    attacks, _ = captures
    assert cli.main(["--data", str(attacks), "--model", str(tmp_path / "m.pkl"), "selfcheck"]) == 2


def test_train_warns_without_a_baseline(tmp_path, captures, capsys):
    attacks, _ = captures
    assert cli.main(["--data", str(attacks), "--model", str(tmp_path / "m.pkl"), "train"]) == 0
    assert "known-good traffic" in capsys.readouterr().err


def test_missing_data_is_an_error_not_a_traceback(tmp_path, capsys):
    code = cli.main(["--data", str(tmp_path / "absent.csv"), "--model",
                     str(tmp_path / "m.pkl"), "train"])
    assert code == 1
    assert capsys.readouterr().err.startswith("Error:")


def test_ingest_of_a_bad_capture_is_an_error(tmp_path, capsys):
    pytest.importorskip("scapy.all")
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture")
    assert cli.main(["ingest", str(junk), "--output", str(tmp_path / "o.csv")]) == 1
    assert "Error:" in capsys.readouterr().err


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.20"])
def test_serve_refuses_a_routable_bind_without_a_token(host, capsys, never_start_a_real_server):
    """An unauthenticated service off loopback exposes the traffic analysis."""
    assert cli.main(["serve", "--host", host, "--port", "5099"]) == 2
    assert "Refusing to listen" in capsys.readouterr().err
    assert never_start_a_real_server == {}


def test_empty_host_env_counts_as_every_interface(monkeypatch, capsys):
    """Werkzeug reads HOST= as all interfaces, so it must be refused too."""
    monkeypatch.setenv("HOST", "")
    assert cli.main(["serve", "--port", "5099"]) == 2


def test_empty_host_flag_falls_back_to_loopback(never_start_a_real_server):
    """`--host ""` means "not given", which defaults to the safe choice."""
    assert cli.main(["serve", "--host", "", "--port", "5099"]) == 0
    assert never_start_a_real_server["host"] == "127.0.0.1"


def test_serve_allows_a_routable_bind_with_a_token(monkeypatch, never_start_a_real_server):
    monkeypatch.setenv("API_TOKEN", "x" * 32)
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "5099"]) == 0
    assert never_start_a_real_server["host"] == "0.0.0.0"
