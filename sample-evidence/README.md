# Sample Forensic Evidence Fixtures

This directory contains synthetic mock evidence fixtures used for local container verification, unit tests, and CI/CD validation.

> [!NOTE]
> All files in this directory are non-sensitive, synthetic test data. They contain no real customer evidence, production credentials, or secrets.

## Included Fixtures

- `syslog.log`: Synthetic Linux system syslog event records.
- `auth.log`: Synthetic Linux authentication events (sshd, sudo).

## Usage

Mount this directory read-only into the forensic analyzer container:

```bash
docker run --rm \
  -v "$(pwd)/sample-evidence:/workspace/input:ro" \
  -v "$(pwd)/sample-evidence-output:/workspace/output" \
  react-forensic-analyzer:local
```
