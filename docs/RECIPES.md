# Recipes

Practical patterns for using `surface-audit` in CI, preview environments,
and LLM-assisted workflows.

## Preview / staging smoke test

Use this when you already know the target URL and want a fast gate
before deploy or promotion:

```bash
surface-audit scan "$PREVIEW_URL" \
    --scope-host preview.example.com \
    --fail-on HIGH \
    --output reports/preview.sarif \
    --format sarif
```

Why it works well:

- `--scope-host` prevents accidental off-target scans
- `--fail-on` turns findings into a CI gate
- SARIF uploads cleanly into GitHub code scanning

## Baseline adoption mode

Adopt the tool without breaking every existing environment on day one:

```bash
# Capture the current known state once
surface-audit scan https://staging.example.com \
    --output reports/baseline.json \
    --format json

# Fail only on newly introduced HIGH+ findings
surface-audit scan https://staging.example.com \
    --baseline reports/baseline.json \
    --fail-on HIGH
```

## Security regression diff

When a deployment changes the attack surface, the diff view is often
more valuable than the raw report:

```bash
surface-audit diff reports/before.json reports/after.json \
    --output reports/diff.json \
    --fail-on-new
```

Use this for "what got worse?" workflows after infrastructure or
framework upgrades.

## GitHub Action

The repository now ships a reusable action at the repo root:

```yaml
- name: Run surface-audit
  uses: dev-ugurkontel/surface-audit@v1
  with:
    target: ${{ steps.preview.outputs.url }}
    scope-hosts: preview.example.com
    output: reports/surface-audit.sarif
    format: sarif
    fail-on: HIGH

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: reports/surface-audit.sarif
```

Use `@v1` for the stable major line, or pin an exact action version
such as `@v1.0.2` when you want fully reproducible workflow inputs.

## Preview workflow with baseline diff and SARIF upload

For regression-focused pull request gating, keep a trusted baseline JSON
file in the repository and compare the current preview against it:

```bash
# Capture once from a trusted branch and commit the file:
surface-audit scan https://preview.example.com \
    --scope-host preview.example.com \
    --output .surface-audit/preview-baseline.json \
    --format json
```

Then use a CI job like this:

```yaml
name: Preview security gate

on:
  pull_request:

jobs:
  surface-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6

      # Replace this with however your preview URL is discovered.
      - name: Resolve preview URL
        id: preview
        run: echo "url=https://preview.example.com" >> "$GITHUB_OUTPUT"

      - name: Install surface-audit
        run: python -m pip install surface-audit==1.0.2

      - name: Capture current JSON report
        run: |
          mkdir -p reports
          surface-audit scan "${{ steps.preview.outputs.url }}" \
            --scope-host preview.example.com \
            --output reports/current.json \
            --format json

      - name: Diff against the trusted baseline
        run: |
          surface-audit diff \
            .surface-audit/preview-baseline.json \
            reports/current.json \
            --output reports/diff.json \
            --fail-on-new

      - name: Emit SARIF for GitHub code scanning
        if: always()
        run: |
          surface-audit scan "${{ steps.preview.outputs.url }}" \
            --scope-host preview.example.com \
            --baseline .surface-audit/preview-baseline.json \
            --output reports/surface-audit.sarif \
            --format sarif \
            --fail-on HIGH \
            --quiet

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: reports/surface-audit.sarif

      - name: Upload raw reports
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: surface-audit-reports
          path: reports/
```

Why this recipe works:

- the checked-in baseline keeps PR runs deterministic
- `diff --fail-on-new` answers "what got worse?" directly
- SARIF still lands in GitHub code scanning for reviewer visibility
- the raw JSON and diff artifacts remain available for debugging

## MCP allow-list pattern

When exposing the scanner to an LLM client, keep it bounded to known
hosts:

```bash
pip install "surface-audit[mcp]"
surface-audit mcp-serve \
    --allow-host staging.example.com \
    --allow-host preview.example.com
```

This is the safest default for agent-driven use because requests to
other hosts are rejected explicitly instead of being retried blindly.

## Container usage

The project ships a Dockerfile for hermetic CLI usage:

```bash
docker build -t surface-audit:local .
docker run --rm surface-audit:local scan https://example.com
```

Tagged releases are also configured to publish a container image to
GHCR so teams can standardize on a pinned image in CI:

```bash
docker pull ghcr.io/dev-ugurkontel/surface-audit:latest
docker run --rm ghcr.io/dev-ugurkontel/surface-audit:latest \
    scan https://example.com --fail-on HIGH
```

Use `:latest` for convenience or a versioned tag such as `:1.0.2` when
you want an immutable container reference.
