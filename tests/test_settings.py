from pathlib import Path

import pytest

from bluesec1_client import RunCapacityExceededError
from sibyl_h0und import cli
from sibyl_h0und.settings import Settings


def test_env_example_contains_complete_runnable_configuration(monkeypatch) -> None:
    """The committed example should satisfy every required setting."""
    monkeypatch.delenv("LLM_CHALLENGER_MODEL", raising=False)
    env_example = Path(__file__).resolve().parents[1] / ".env.example"

    settings = Settings(_env_file=env_example)

    assert settings.scenario_runtime_endpoint == "bluesec.team:443"
    assert settings.scenario_runtime_verify_tls is True
    assert settings.scenario_runtime_arena is None
    assert settings.llm_base_url == "https://provider.example/v1"
    assert settings.llm_api_key.get_secret_value() == "replace-with-your-key"
    assert settings.llm_default_model == "provider/model-name"
    assert settings.llm_challenger_model is None
    assert settings.agent_max_runtime_calls == 95


def test_runtime_call_ceiling_must_stay_below_the_runtime_limit(monkeypatch) -> None:
    """A ceiling of 100 would let the runtime end a task before the report."""
    env_example = Path(__file__).resolve().parents[1] / ".env.example"
    monkeypatch.setenv("BLUESEC_AGENT_MAX_RUNTIME_CALLS", "100")

    with pytest.raises(ValueError):
        Settings(_env_file=env_example)


def test_only_a_set_challenger_model_replaces_the_default_one(monkeypatch) -> None:
    """Unset or blank, the challenger shares the default model; set, it gets its own."""
    env_example = Path(__file__).resolve().parents[1] / ".env.example"
    monkeypatch.delenv("LLM_CHALLENGER_MODEL", raising=False)

    assert cli.role_models(Settings(_env_file=env_example)) == {}

    monkeypatch.setenv("LLM_CHALLENGER_MODEL", " ")
    assert cli.role_models(Settings(_env_file=env_example)) == {}

    monkeypatch.setenv("LLM_CHALLENGER_MODEL", "provider/challenger")
    assert cli.role_models(Settings(_env_file=env_example)) == {
        "challenger": "provider/challenger",
        "answer_review": "provider/challenger",
    }


def test_missing_configuration_is_reported_without_traceback(monkeypatch, capsys):
    for name in ("SCENARIO_RUNTIME_TOKEN", "LLM_BASE_URL", "LLM_API_KEY", "LLM_DEFAULT_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(Settings.model_config, "env_file", Path("/nonexistent/.env"))

    with pytest.raises(SystemExit) as exit_info:
        cli.load_settings()

    assert exit_info.value.code == 1
    message = capsys.readouterr().err
    assert "Missing configuration" in message
    assert "SCENARIO_RUNTIME_TOKEN" in message
    assert "Traceback" not in message


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("SUBJECT_ACTIVE_RUN_LIMIT_REACHED", "your limit of concurrent runs"),
        ("PROCESS_ACTIVE_RUN_LIMIT_REACHED", "not your limit"),
    ],
)
def test_run_capacity_message_depends_on_reason(reason: str, expected: str) -> None:
    error = RunCapacityExceededError("capacity reached", reason=reason)

    message = cli._run_capacity_message(error)

    assert expected in message
