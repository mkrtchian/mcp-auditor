from pathlib import Path
from typing import Any

import yaml


def a_config_file_containing(tmp_path: Path, **entries: Any) -> Path:
    path = tmp_path / ".mcp-auditor.yml"
    path.write_text(yaml.dump(entries))
    return path
