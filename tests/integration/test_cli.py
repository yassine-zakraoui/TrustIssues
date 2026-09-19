import json
import runpy
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from tests.conftest import ROOT

pytestmark = pytest.mark.integration
runner = CliRunner()


def invoke(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, list(args))
    return result.exit_code, result.output


def test_scenarios_validate_and_list() -> None:
    code, output = invoke("scenarios", "validate", str(ROOT / "scenarios"), "--json")
    data = json.loads(output)
    assert code == 0 and data["checked"] == 28 and data["failed"] == 0
    code, output = invoke("scenarios", "list", str(ROOT / "scenarios" / "public"), "--json")
    assert code == 0 and len(json.loads(output)) == 19


def test_scenarios_validate_reports_problems(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: Bad\nversion: 0\n")
    code, output = invoke("scenarios", "validate", str(bad), "--json")
    assert code == 1
    problems = json.loads(output)["results"][0]["problems"]
    assert any(p.startswith("id:") for p in problems) and any("turns" in p for p in problems)


def test_schema_export(tmp_path: Path) -> None:
    out = tmp_path / "schema.json"
    code, _ = invoke("scenarios", "schema", "--out", str(out))
    assert code == 0 and json.loads(out.read_text())["title"] == "Scenario"
    committed = json.loads((ROOT / "scenarios" / "schemas" / "scenario.schema.json").read_text())
    assert committed == json.loads(out.read_text()), "run `make schema` to refresh the committed schema"


def test_run_eval_and_replay(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    code, output = invoke(
        "run",
        "--scenario",
        str(ROOT / "scenarios/public/soc/soc_hostile_log_text.yaml"),
        "--defense",
        "provenance",
        "--artifacts",
        str(artifacts),
        "--json",
    )
    assert code == 0, output
    data = json.loads(output)
    assert data["outcome"]["attack_success"] is False
    code, output = invoke("replay", data["artifact"])
    assert code == 0 and "defense" in output and "task_success" in output

    first = json.loads(
        invoke("eval", "validation", "--defense", "provenance", "--artifacts", str(artifacts), "--json")[1]
    )
    second = json.loads(
        invoke("eval", "validation", "--defense", "provenance", "--artifacts", str(artifacts), "--json")[1]
    )
    assert first["deterministic_digest"] == second["deterministic_digest"]
    assert first["scenario_count"] == 9 and first["score"]["config_final"] is False
    assert len(list((artifacts / "scorecards").glob("*.json"))) == 2


def test_eval_argument_errors(tmp_path: Path) -> None:
    code, _ = invoke("eval", "public", "--artifacts", str(tmp_path))
    assert code != 0
    code, _ = invoke(
        "eval", "public", "--defense", "allow_all", "--defense-url", "http://x", "--artifacts", str(tmp_path)
    )
    assert code != 0
    code, _ = invoke("eval", "public", "--defense", "no_such_defense", "--artifacts", str(tmp_path))
    assert code != 0
    code, _ = invoke(
        "eval",
        "validation",
        "--defense",
        "allow_all",
        "--scenarios",
        str(ROOT / "scenarios/public"),
        "--artifacts",
        str(tmp_path),
    )
    assert code != 0


def test_submission_validate_command() -> None:
    code, output = invoke("submission", "validate", str(ROOT / "starter-kits/python-defense"), "--json")
    assert code == 0 and json.loads(output)["ok"] is True


def test_fixture_and_scenario_generation_is_reproducible(tmp_path: Path) -> None:
    fixtures = runpy.run_path(str(ROOT / "scripts/generate_fixture_data.py"))
    for domain in ("enterprise", "finance", "soc"):
        generated = json.dumps(fixtures[domain](), indent=2, sort_keys=True) + "\n"
        assert generated == (ROOT / "fixtures" / domain / "base.json").read_text()
    scenarios = runpy.run_path(str(ROOT / "scripts/generate_public_scenarios.py"))
    for item in scenarios["enterprise_public"]() + scenarios["finance_public"]() + scenarios["soc_public"]():
        path = tmp_path / f"{item['id']}.yaml"
        scenarios["dump"](item, path)
        assert path.read_text() == (ROOT / "scenarios/public" / item["domain"] / path.name).read_text()
