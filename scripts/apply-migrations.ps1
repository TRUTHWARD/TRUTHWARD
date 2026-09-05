# SPDX-License-Identifier: Apache-2.0
param(
  [string]$DatabaseUrl = "",
  [string]$MigrationsDir = "",
  [switch]$FreshSchema,
  [string]$SchemaFile = "",
  [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
. "$PSScriptRoot\smoke-wrapper-lib.ps1"
$python = Resolve-SmokePython -RepoRoot $root -PythonExecutable $PythonExecutable -SkipDependencyProbe
$arguments = @((Join-Path $PSScriptRoot "apply_migrations.py"))
if ($FreshSchema) { $arguments += "--fresh-schema" }
if ($MigrationsDir) { $arguments += @("--migrations-dir", $MigrationsDir) }
if ($SchemaFile) { $arguments += @("--schema-file", $SchemaFile) }

# Windows compatibility only. Python owns SQL, checksums, locking and the ledger.
# Forward an explicitly supplied DSN in the child environment, never in argv.
$previousDatabaseUrl = $env:DATABASE_URL
try {
  if ($DatabaseUrl) { $env:DATABASE_URL = $DatabaseUrl }
  & $python.FilePath @($python.PrefixArgs) @arguments
  $migrationExitCode = $LASTEXITCODE
}
finally {
  if ($null -eq $previousDatabaseUrl) {
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
  }
  else {
    $env:DATABASE_URL = $previousDatabaseUrl
  }
}
exit $migrationExitCode
