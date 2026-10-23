"""Tests for forensic analyzer container entrypoint behavior."""

import os
import pathlib
import stat
import subprocess


def _write_executable(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    current_mode = path.stat().st_mode
    path.chmod(current_mode | stat.S_IXUSR)


def _entrypoint_path() -> pathlib.Path:
    return (
        pathlib.Path(__file__).resolve().parents[2]
        / "src"
        / "containers"
        / "forensic-analyzer"
        / "entrypoint.sh"
    )


def test_entrypoint_fails_for_empty_input(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()

    result = subprocess.run(
        ["bash", str(_entrypoint_path())],
        env={
            **os.environ,
            "FORENSIC_INPUT_DIR": str(input_dir),
            "FORENSIC_OUTPUT_DIR": str(output_dir),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "No evidence found under" in result.stderr


def test_entrypoint_runs_plaso_pipeline_and_writes_timeline_json(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    storage_path = tmp_path / "storage" / "timeline.plaso"
    bin_dir = tmp_path / "bin"
    input_dir.mkdir()
    bin_dir.mkdir()

    (input_dir / "disk-image.E01").write_bytes(b"fake evidence")

    fake_log2timeline = bin_dir / "log2timeline.py"
    _write_executable(
        fake_log2timeline,
        """#!/usr/bin/env bash
set -euo pipefail
storage=""
sources=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    --parsers|--partitions|--vss_stores|--status_view)
      shift 2
      ;;
    *)
      sources+=("$1")
      shift
      ;;
  esac
done
[[ -n "$storage" ]]
[[ "${#sources[@]}" -gt 0 ]]
printf '{"storage":"ok"}\n' > "$storage"
""",
    )

    fake_psort = bin_dir / "psort.py"
    _write_executable(
        fake_psort,
        """#!/usr/bin/env bash
set -euo pipefail
output=""
storage=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--write)
      output="$2"
      shift 2
      ;;
    -o|--status_view)
      shift 2
      ;;
    *)
      storage="$1"
      shift
      ;;
  esac
done
[[ -s "$storage" ]]
[[ -n "$output" ]]
printf '{"message":"timeline event"}\n' > "$output"
""",
    )

    result = subprocess.run(
        ["bash", str(_entrypoint_path())],
        env={
            **os.environ,
            "FORENSIC_INPUT_DIR": str(input_dir),
            "FORENSIC_OUTPUT_DIR": str(output_dir),
            "FORENSIC_STORAGE_PATH": str(storage_path),
            "LOG2TIMELINE_BIN": str(fake_log2timeline),
            "PSORT_BIN": str(fake_psort),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    timeline_file = output_dir / "timeline.json"
    assert result.returncode == 0, result.stderr
    assert timeline_file.exists()
    assert timeline_file.read_text(encoding="utf-8").strip() == '{"message":"timeline event"}'
