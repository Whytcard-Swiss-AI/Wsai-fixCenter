import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def test_wheel_contains_all_public_skills(tmp_path):
    source = Path(__file__).resolve().parents[1]
    project = tmp_path / "project"
    shutil.copytree(
        source,
        project,
        ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", "build", "dist", "work", "*.egg-info"
        ),
    )
    output = tmp_path / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(output)],
        check=True,
        capture_output=True,
        text=True,
        cwd=project,
    )
    wheel = next(output.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    for skill in ("fixcenter-install", "fixcenter-use", "fixcenter-setup"):
        assert any(name.endswith(f"/skills/{skill}/SKILL.md") for name in names)
        assert any(
            name.endswith(f"/skills/{skill}/agents/openai.yaml") for name in names
        )
