# Reference contributor adapters

These Apache-2.0 reference adapters implement the minimum public Batch 31
contracts without external services. They are examples, not product runtime
bindings and not evidence of a vendor tool/provider call.

Run all three from a clean clone after installing backend dependencies:

```powershell
.\scripts\run-contributor-conformance.ps1
```

Test one contributor module:

```powershell
.\scripts\run-contributor-conformance.ps1 `
  -Kind runner `
  -AdapterPath C:\path\to\my_runner.py
```

Each module exposes a documented factory. The command never registers a Skill,
does not create a Skill Invocation, and does not write product state.
