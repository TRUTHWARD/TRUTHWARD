# Deterministic public quality sample

This repository-authored sample is the public target for Batch 31 / TST-P2-032.
It is an OSS export candidate licensed under
[Apache License 2.0](../../release/oss/LICENSE) when included in an approved
OSS distribution; provenance is
recorded in [NOTICE](NOTICE). There are no third-party assets.

The app deliberately contains seven independently reviewable defects:

- two functional defects;
- one deterministic performance defect;
- four security defects.

The authoritative, public oracle is
[`benchmarks/public_quality/expected-findings.v1.json`](../../benchmarks/public_quality/expected-findings.v1.json).
The safe controls and benchmark coverage are published beside it. Expected
outputs are not hidden and the observation/model-stub path does not read the
oracle before scoring.

## Safety

The server refuses non-loopback bind addresses. The exposed credential is a
synthetic fixed canary, the SQL-injection example is never executed, and the
application performs no external network access or persistent writes.

Run it manually:

```powershell
py -3.14 .\examples\public_quality_benchmark\app.py --port 8765
```

Then open `http://127.0.0.1:8765/`. The benchmark starts its own ephemeral
loopback instance, so manual startup is not required for the public command.
