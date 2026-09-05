# Community local Skill manifests

The OSS profile reads data-only `*.json` manifests from this directory (or from
`COMMUNITY_SKILL_MANIFEST_DIR`). Registration never loads source code, scripts,
binaries, or remote URLs. A manifest may only select a runtime adapter already
compiled into the service and allowed by an existing extension point contract.

The included `regression-scope-local.example.json` version `1.1.0` is an executable
presentation extension for the existing regression recommendation. Its compiled
adapter `community.regression_projection.v1` groups cases already selected by the
Service; it does not select or execute tests, change priorities, or make decisions.

1. Register the manifest in **Capability bindings**.
2. Select `PREPARE.regression_scope` and `regression-scope-local` version `1.1.0`.
3. Create a project- or environment-scoped **draft** binding.
4. Click **Enable binding**. The backend validates the exact contract, scope,
   manifest hash, stop switches and presentation conformance before enabling it.
5. Open an Execution and click **Generate regression view**. Inspect its grouped
   cases, resolved Skill and Invocation ID; the Invocation identifies the binding.
6. Click **Disable binding** when finished. Later calls use the existing default
   resolution; past invocations retain their frozen version and result.

Customize the data-only profile by creating a new manifest/version:

```json
"communityProfile": {"groupBy": "priority", "includeCaseIds": false}
```

`groupBy` accepts `domain` or `priority`; `includeCaseIds` must be a JSON boolean.
The profile belongs inside `compatibility`. Keep the remaining contract and
permissions unchanged. Registered versions are immutable; use a new version for
changes. Disable the previous binding before enabling another at the same scope.

Only this exact presentation contract supports Community enablement. Other
registered manifests may remain draft and show enablement as unavailable.
This policy does not expose Evaluation, Shadow, Approval or automatic rollback.
Direct Skill invocation remains disabled; business workflows own invocation.
See [enablement contract](../docs/COMMUNITY_SKILL_ENABLEMENT.md).

Only low-risk data-only manifests with empty `allowedTools` and
`allowedConnectors` are accepted. No scripts, arbitrary code, external writes,
database/Memory/Gate access, symlinks or remote downloads are allowed.
