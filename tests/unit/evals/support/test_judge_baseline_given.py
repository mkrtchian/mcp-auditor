import json
from pathlib import Path

from tests.unit.evals.support.judge_baselines import a_baseline


def a_baseline_file_keyed_replay_rule(tmp_path: Path) -> Path:
    written = a_baseline().model_dump(mode="json")
    written["replay_rule"] = written.pop("retest_rule")
    path = tmp_path / "judge.json"
    path.write_text(json.dumps(written))
    return path
