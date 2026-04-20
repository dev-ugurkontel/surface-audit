# Report schema

The JSON report produced by `surface-audit scan -f json` is intended as
a stable machine contract. Its shape is described by
[`schemas/report.schema.json`](../schemas/report.schema.json), which
uses [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/schema).

## Top-level fields

| Field                  | Type                    | Description                                                     |
| ---------------------- | ----------------------- | --------------------------------------------------------------- |
| `target`               | object                  | Canonical target URL, hostname, port, and scheme.               |
| `started_at`           | RFC 3339 string         | When the scan began (UTC).                                      |
| `finished_at`          | RFC 3339 string \| null | When the scan finished, or null if the scan was interrupted.    |
| `duration_seconds`     | number                  | Wall-clock scan duration.                                       |
| `summary.total`        | integer                 | Count of findings.                                              |
| `summary.by_severity`  | object                  | Counts keyed by severity name.                                  |
| `summary.max_severity` | string \| null          | Worst severity present, or null when the report is empty.       |
| `findings`             | array                   | Individual findings. See below.                                 |
| `errors`               | array of strings        | Non-fatal errors raised during the scan (one per failed check). |

## Finding shape

| Field            | Type           | Description                                             |
| ---------------- | -------------- | ------------------------------------------------------- |
| `check_id`       | string         | ID of the emitting check (e.g. `csrf`).                 |
| `title`          | string         | Short, human-readable summary.                          |
| `severity`       | enum           | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO`.    |
| `description`    | string         | Why the finding matters, referencing observed evidence. |
| `recommendation` | string         | Concrete fix.                                           |
| `category`       | string         | OWASP Top 10 (2021) category label.                     |
| `location`       | string \| null | URL most directly associated with the finding.          |
| `evidence`       | string \| null | Raw signal that triggered the finding.                  |
| `references`     | array of URIs  | External references (MDN, OWASP, RFC).                  |

## Compatibility guarantees

`surface-audit` uses semantic versioning. On the `1.x` line:

- Existing fields will never be removed without a major-version bump.
- Existing field types will not change.
- New fields may be added; consumers must tolerate unknown keys.

Every schema change — even additive — lands in
[`CHANGELOG.md`](../CHANGELOG.md) with the release that introduced it.

## Validating a report

```bash
pip install check-jsonschema
check-jsonschema --schemafile schemas/report.schema.json reports/example.json
```

Or from Python:

```python
import json
from pathlib import Path
from jsonschema import Draft202012Validator

schema = json.loads(Path("schemas/report.schema.json").read_text())
report = json.loads(Path("reports/example.json").read_text())
Draft202012Validator(schema).validate(report)
```

## Diff format

The `diff` subcommand emits a related-but-separate shape: an object
with `added`, `removed`, `unchanged` (lists of findings) and a `summary`
object. The finding structure inside each list matches the schema
above.
