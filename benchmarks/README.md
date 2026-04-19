# Benchmarks

`benchmarks/run.py` measures the wall-clock cost of a single scan with
every HTTP call intercepted locally. It is a **regression guard**, not
a marketing figure — absolute numbers depend on the machine, so the
interesting quantity is the _trend_ across commits.

## Method

- All 13 checks run against `https://example.com`.
- The TLS check is disabled because it opens a real socket, which
  bypasses the HTTP mock.
- Every other check's HTTP traffic is answered by a single in-process
  mock that returns a minimal hardened response.
- 3 warm-up iterations absorb import and regex-compile work; 20
  measurement iterations are averaged.

## Reading the output

```text
iterations: 20 (after 3 warmup)
mean:         45.2 ms
median:       44.8 ms
stdev:         1.8 ms
min:          43.1 ms
max:          49.6 ms
```

Watch `median` across commits. A sudden 2-3× regression signals that a
new check, retry path, or plugin discovery loop has introduced
unnecessary synchronous work on the hot path.

## Running

```bash
pip install -e ".[dev]"
python benchmarks/run.py
```

No output file is written; redirect stdout if you want to log results.
