# Architecture

This document explains how `surface-audit` is organized and why. It is
aimed at contributors and anyone wanting to embed the library into a
larger tool.

## Goals

1. **Extensible** — new checks and report formats ship as regular
   Python packages, registered via entry points. No fork required.
2. **Predictable** — a scan is a pure function of configuration and
   HTTP responses. Renderers are deterministic.
3. **Ethical by default** — polite defaults (capped concurrency, no
   retry storms, bounded request volume).
4. **Typed, tested, small** — every public symbol carries types; every
   production module has 100 % line and branch coverage; the core stays
   under 1.5 k lines.

## Layered view

```
┌──────────────────────────────────────────────────────────────┐
│  presentation    (cli.py, mcp_server.py)                     │
│    ↓ parses args / MCP tools, owns exit codes, logging       │
├──────────────────────────────────────────────────────────────┤
│  application     (scanner.py, diff.py)                       │
│    ↓ orchestrates checks, aggregates findings, diffs reports │
├──────────────────────────────────────────────────────────────┤
│  domain          (models, exceptions, scope, checks/base)    │
│    ↓ Finding, ScanTarget, Severity, Check, ScopePolicy       │
├──────────────────────────────────────────────────────────────┤
│  infrastructure  (client.py, reporting/, config.py)          │
│      httpx-backed HTTPClient with retry policy               │
│      Renderer protocol + console/JSON/HTML/SARIF/Markdown    │
│      TOML config loader with schema validation               │
└──────────────────────────────────────────────────────────────┘
```

- **Presentation** depends on every layer beneath it but nothing above.
- **Application** depends only on the domain and infrastructure.
- **Domain** depends on nothing project-internal — it is the stable core.
- **Infrastructure** implements what the domain declares via Protocols
  and ABCs.

## Module map

| Module                                            | Responsibility                                                   |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| `models.py`                                       | Value objects: `Finding`, `Severity`, `ScanTarget`, `ScanReport` |
| `exceptions.py`                                   | Typed exception hierarchy rooted at `SurfaceAuditError`          |
| `scope.py`                                        | `ScopePolicy` — shared host allow-list for CLI and MCP           |
| `checks/base.py`                                  | `Check` ABC, `CheckContext` DTO, `NETWORK_ERRORS` tuple          |
| `checks/*.py`                                     | 13 concrete checks, one per file                                 |
| `client.py`                                       | `HTTPClient` async wrapper + `RetryPolicy`                       |
| `config.py`                                       | TOML config loader with schema validation                        |
| `scanner.py`                                      | `Scanner` orchestrator + `ScannerConfig`                         |
| `diff.py`                                         | Baseline suppression + finding-level report diff                 |
| `reporting/base.py`                               | `Renderer` Protocol + `REGISTRY` + `render`/`write`              |
| `reporting/{console,json,html,sarif,markdown}.py` | Built-in renderers, each self-registers                          |
| `cli.py`                                          | Typer app, logging setup, exit-code policy                       |
| `mcp_server.py`                                   | FastMCP server over stdio; optional `[mcp]` extra                |

## Design patterns in use

### Strategy — checks

Every check is a strategy for producing findings. The `Check` ABC is
the interface; concrete subclasses swap behavior. The `Scanner` never
branches on check type.

### Strategy + Registry — renderers

Rendering is a callable satisfying the `Renderer` protocol; each
concrete module registers itself against `reporting.REGISTRY`. Adding
HTML output did not require touching the scanner or the CLI.

### Plugin architecture — entry points

`pyproject.toml` declares `surface_audit.checks` entry points. Any
third-party wheel that exposes the same group extends the built-in
set at runtime without code changes.

### Dependency Inversion — `CheckContext`

Checks do not import `HTTPClient` directly. They receive a read-only
`CheckContext` DTO containing the target, client and config. This
means checks can be tested against mock transports with ease.

### Value objects — frozen dataclasses

`Finding`, `ScanTarget`, and `RetryPolicy` are all `@dataclass(frozen=True, slots=True)`.
Immutability means equality is structural, serialization is deterministic,
and no check can mutate shared state.

### Context manager — `HTTPClient`

Resource ownership is explicit: `async with HTTPClient(...)`. Connection
pooling and TLS contexts are torn down even if a check raises.

## SOLID scorecard

- **S**ingle Responsibility — each module changes for one reason
  (renderers change when output formats evolve; checks change when the
  threat model evolves; the scanner changes when orchestration rules do).
- **O**pen/Closed — checks and renderers are added by registration, not
  by editing existing code.
- **L**iskov — `Check` declares contract (`run(ctx) -> list[Finding]`)
  and every subclass honors it; there is no "this one also does X".
- **I**nterface Segregation — `Check` has one method; `Renderer` is a
  single-method `Protocol`. Nothing is forced to implement unused API.
- **D**ependency Inversion — higher layers depend on abstractions
  (`Check`, `Renderer`). Concrete types are wired at the composition
  root (`scanner.py`, `cli.py`).

## Control flow of a scan

1. `cli.scan` parses arguments and merges with the TOML config file.
2. It constructs a `ScannerConfig` and a `Scanner`.
3. `Scanner.run()` opens the shared `HTTPClient`, builds a
   `CheckContext`, and dispatches each selected `Check.run` as a task.
4. `asyncio.gather(..., return_exceptions=True)` collects both findings
   and failures — one broken check cannot abort the scan.
5. Findings are aggregated into a `ScanReport`; errors are recorded
   structurally.
6. The CLI renders to stdout via `render_console` and optionally writes
   a machine format via `reporting.write`.

## Concurrency model

- A single event loop (`asyncio.run`) drives the whole scan.
- All HTTP I/O is async through `httpx.AsyncClient`.
- The `HTTPClient` semaphore caps in-flight requests globally so a check
  that fires parallel probes (e.g. `misconfiguration`) cannot starve
  the rest.
- SSL handshakes happen on a threadpool (`loop.run_in_executor`)
  because `ssl.SSLSocket` APIs are blocking.

## Extension points

| Want to...              | Do this                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| Add a check             | Subclass `Check`, register under the `surface_audit.checks` entry-point group                           |
| Add a report format     | Write a `Renderer` callable and register under `surface_audit.renderers` or call `register("name", fn)` |
| Change retry behavior   | Pass a custom `RetryPolicy` into `HTTPClient`                                                           |
| Replace the HTTP client | Implement the two methods `Check` uses (`get`/`head`) and inject via a custom `Scanner` subclass        |
| Drive scans from an LLM | `surface-audit mcp-serve` exposes a Model Context Protocol stdio server (see `mcp_server.py`)           |
| Change CLI UX           | Wrap the library; the core exposes a typed API                                                          |

## Non-goals

- Crawling. The scanner hits one target URL plus a bounded set of
  well-known paths. Extending to crawling changes the threat model
  (rate limiting, scope creep, legal posture) and belongs in a
  different tool.
- Exploit confirmation. All checks are read-only heuristics. Findings
  are signals, not proof.
- Authenticated scanning. Not yet. Session handling would add a
  stateful dimension we do not want to carry lightly.
