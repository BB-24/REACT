"""Tests for forensic analyzer container entrypoint behavior."""

import os
import pathlib
import shutil
import stat
import subprocess

import pytest


def _find_bash() -> str | None:
    if os.name == "nt":
        for candidate in [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]:
            if os.path.exists(candidate):
                return candidate
    return shutil.which("bash")


BASH_BIN = _find_bash()

pytestmark = pytest.mark.skipif(
    BASH_BIN is None,
    reason="bash executable not available in environment",
)


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


def _run_entrypoint(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    assert BASH_BIN is not None
    return subprocess.run(
        [BASH_BIN, _entrypoint_path().as_posix()],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_entrypoint_fails_for_missing_input(tmp_path):
    input_dir = tmp_path / "nonexistent-input"
    output_dir = tmp_path / "output"

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
        }
    )

    assert result.returncode != 0
    assert "Input directory not found" in result.stderr


def test_entrypoint_fails_for_empty_input(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
        }
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
has_parsers=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    --parsers)
      has_parsers=true
      shift 2
      ;;
    --partitions|--vss_stores|--status_view)
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
[[ "$has_parsers" == true ]]
mkdir -p "$(dirname "$storage")"
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

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
            "FORENSIC_STORAGE_PATH": storage_path.as_posix(),
            "LOG2TIMELINE_BIN": fake_log2timeline.as_posix(),
            "PSORT_BIN": fake_psort.as_posix(),
        }
    )

    timeline_file = output_dir / "timeline.json"
    assert result.returncode == 0, result.stderr
    assert "using configured parsers mode" in result.stderr
    assert timeline_file.exists()
    assert timeline_file.read_text(encoding="utf-8").strip() == '{"message":"timeline event"}'


def test_entrypoint_parser_fallback_to_default_parsers(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    storage_path = tmp_path / "storage" / "timeline.plaso"
    bin_dir = tmp_path / "bin"
    input_dir.mkdir()
    bin_dir.mkdir()

    (input_dir / "syslog.log").write_bytes(b"Oct 24 00:00:01 mock log event")

    fake_log2timeline = bin_dir / "log2timeline.py"
    _write_executable(
        fake_log2timeline,
        """#!/usr/bin/env bash
set -euo pipefail
storage=""
sources=()
has_parsers=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    --parsers)
      has_parsers=true
      shift 2
      ;;
    --partitions|--vss_stores|--status_view)
      shift 2
      ;;
    *)
      sources+=("$1")
      shift
      ;;
  esac
done

# If --parsers is provided, simulate failure due to unsupported parser names
if [[ "$has_parsers" == true ]]; then
  echo "Plaso error: unsupported parser specified" >&2
  exit 1
fi

[[ -n "$storage" ]]
[[ "${#sources[@]}" -gt 0 ]]
mkdir -p "$(dirname "$storage")"
printf '{"storage":"fallback_default_ok"}\n' > "$storage"
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
printf '{"timestamp":"2026-10-24T00:00:01Z","event":"mock syslog event"}\n' > "$output"
""",
    )

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
            "FORENSIC_STORAGE_PATH": storage_path.as_posix(),
            "LOG2TIMELINE_BIN": fake_log2timeline.as_posix(),
            "PSORT_BIN": fake_psort.as_posix(),
        }
    )

    timeline_file = output_dir / "timeline.json"
    assert result.returncode == 0, result.stderr
    assert "failed with configured parsers" in result.stderr
    assert "Safely retrying using Plaso default parser set mode" in result.stderr
    assert "using Plaso default parser set mode" in result.stderr
    assert timeline_file.exists()
    assert "mock syslog event" in timeline_file.read_text(encoding="utf-8")


def test_entrypoint_runs_default_parser_set_directly_when_configured_default(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    storage_path = tmp_path / "storage" / "timeline.plaso"
    bin_dir = tmp_path / "bin"
    input_dir.mkdir()
    bin_dir.mkdir()

    (input_dir / "auth.log").write_bytes(b"Oct 24 00:01:00 auth event")

    fake_log2timeline = bin_dir / "log2timeline.py"
    _write_executable(
        fake_log2timeline,
        """#!/usr/bin/env bash
set -euo pipefail
storage=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    --parsers)
      echo "Error: --parsers was unexpectedly provided" >&2
      exit 1
      ;;
    --partitions|--vss_stores|--status_view)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$storage" ]]
mkdir -p "$(dirname "$storage")"
printf '{"storage":"default_direct_ok"}\n' > "$storage"
""",
    )

    fake_psort = bin_dir / "psort.py"
    _write_executable(
        fake_psort,
        """#!/usr/bin/env bash
set -euo pipefail
output=""
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
      shift
      ;;
  esac
done
[[ -n "$output" ]]
printf '{"message":"direct default event"}\n' > "$output"
""",
    )

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
            "FORENSIC_STORAGE_PATH": storage_path.as_posix(),
            "LOG2TIMELINE_BIN": fake_log2timeline.as_posix(),
            "PSORT_BIN": fake_psort.as_posix(),
            "PLASO_PARSERS": "default",
        }
    )

    assert result.returncode == 0, result.stderr
    assert "using Plaso default parser set mode" in result.stderr
    assert "WARNING" not in result.stderr


def test_entrypoint_preserves_read_only_input(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    storage_path = tmp_path / "storage" / "timeline.plaso"
    bin_dir = tmp_path / "bin"
    input_dir.mkdir()
    bin_dir.mkdir()

    evidence_file = input_dir / "evidence.raw"
    evidence_file.write_bytes(b"readonly-content")
    # Mark evidence read-only
    evidence_file.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    fake_log2timeline = bin_dir / "log2timeline.py"
    _write_executable(
        fake_log2timeline,
        """#!/usr/bin/env bash
set -euo pipefail
storage=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$storage")"
printf '{"storage":"ro_ok"}\n' > "$storage"
""",
    )

    fake_psort = bin_dir / "psort.py"
    _write_executable(
        fake_psort,
        """#!/usr/bin/env bash
set -euo pipefail
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--write)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '{"timeline":"ok"}\n' > "$output"
""",
    )

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
            "FORENSIC_STORAGE_PATH": storage_path.as_posix(),
            "LOG2TIMELINE_BIN": fake_log2timeline.as_posix(),
            "PSORT_BIN": fake_psort.as_posix(),
            "PLASO_PARSERS": "default",
        }
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "timeline.json").exists()


def test_entrypoint_fails_when_timeline_output_empty(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    storage_path = tmp_path / "storage" / "timeline.plaso"
    bin_dir = tmp_path / "bin"
    input_dir.mkdir()
    bin_dir.mkdir()

    (input_dir / "syslog.log").write_bytes(b"sample data")

    fake_log2timeline = bin_dir / "log2timeline.py"
    _write_executable(
        fake_log2timeline,
        """#!/usr/bin/env bash
set -euo pipefail
storage=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-file)
      storage="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$storage")"
printf '{"storage":"ok"}\n' > "$storage"
""",
    )

    # Fake psort creates an empty file
    fake_psort = bin_dir / "psort.py"
    _write_executable(
        fake_psort,
        """#!/usr/bin/env bash
set -euo pipefail
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--write)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
touch "$output"
""",
    )

    result = _run_entrypoint(
        {
            "FORENSIC_INPUT_DIR": input_dir.as_posix(),
            "FORENSIC_OUTPUT_DIR": output_dir.as_posix(),
            "FORENSIC_STORAGE_PATH": storage_path.as_posix(),
            "LOG2TIMELINE_BIN": fake_log2timeline.as_posix(),
            "PSORT_BIN": fake_psort.as_posix(),
            "PLASO_PARSERS": "default",
        }
    )

    assert result.returncode != 0
    assert "Timeline output is missing or empty" in result.stderr
