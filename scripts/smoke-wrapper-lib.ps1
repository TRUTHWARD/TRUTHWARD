# SPDX-License-Identifier: Apache-2.0
$script:SmokeDependencyProbe = "import agentic_qa, pydantic_core, pytest_timeout, yaml"

function Get-SmokePythonRequirement {
  param([Parameter(Mandatory = $true)][string]$RepoRoot)

  $pyproject = Join-Path $RepoRoot "backend\pyproject.toml"
  if (-not (Test-Path -LiteralPath $pyproject -PathType Leaf)) {
    throw "Backend pyproject is unavailable: $pyproject"
  }
  $content = Get-Content -Raw -LiteralPath $pyproject
  $match = [regex]::Match(
    $content,
    '(?m)^\s*requires-python\s*=\s*"(?<specifier>[^"]+)"\s*$'
  )
  if (-not $match.Success) {
    throw "backend/pyproject.toml must declare requires-python."
  }
  $specifier = $match.Groups["specifier"].Value.Replace(" ", "")
  $range = [regex]::Match(
    $specifier,
    '^>=(?<minMajor>\d+)\.(?<minMinor>\d+),<(?<maxMajor>\d+)\.(?<maxMinor>\d+)$'
  )
  if (-not $range.Success) {
    throw "Unsupported requires-python form '$specifier'; expected a closed >=major.minor,<major.minor range."
  }
  return [pscustomobject]@{
    Specifier = $specifier
    MinMajor = [int]$range.Groups["minMajor"].Value
    MinMinor = [int]$range.Groups["minMinor"].Value
    MaxMajor = [int]$range.Groups["maxMajor"].Value
    MaxMinor = [int]$range.Groups["maxMinor"].Value
  }
}

function Get-SmokeRepoRoot {
  param([Parameter(Mandatory = $true)][string]$ScriptRoot)
  return [System.IO.Path]::GetFullPath((Split-Path -Parent $ScriptRoot))
}

function Set-SmokePythonPath {
  param([Parameter(Mandatory = $true)][string]$RepoRoot)

  $entries = @(
    (Join-Path $RepoRoot ".deps"),
    (Join-Path $RepoRoot "backend\src")
  )
  if ($env:PYTHONPATH) {
    $entries += $env:PYTHONPATH
  }
  $env:PYTHONPATH = $entries -join [System.IO.Path]::PathSeparator
}

function Resolve-SmokePython {
  param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [string]$PythonExecutable = "",
    [switch]$SkipDependencyProbe
  )

  Set-SmokePythonPath -RepoRoot $RepoRoot
  $requirement = Get-SmokePythonRequirement -RepoRoot $RepoRoot
  $versionProbe = (
    "import sys; raise SystemExit(0 if ({0}, {1}) <= sys.version_info[:2] < ({2}, {3}) else 1)" -f
      $requirement.MinMajor,
      $requirement.MinMinor,
      $requirement.MaxMajor,
      $requirement.MaxMinor
  )
  $candidates = New-Object System.Collections.Generic.List[object]

  if ($PythonExecutable) {
    $candidates.Add([pscustomobject]@{ FilePath = $PythonExecutable; PrefixArgs = @(); Explicit = $true })
  }
  elseif ($env:SMOKE_PYTHON_EXECUTABLE) {
    $candidates.Add([pscustomobject]@{ FilePath = $env:SMOKE_PYTHON_EXECUTABLE; PrefixArgs = @(); Explicit = $true })
  }
  else {
    foreach ($localCandidate in @(
      (Join-Path $RepoRoot "backend\.venv\Scripts\python.exe"),
      (Join-Path $RepoRoot ".venv\Scripts\python.exe"),
      (Join-Path $RepoRoot "backend/.venv/bin/python"),
      (Join-Path $RepoRoot ".venv/bin/python")
    )) {
      if (Test-Path -LiteralPath $localCandidate -PathType Leaf) {
        $candidates.Add([pscustomobject]@{ FilePath = $localCandidate; PrefixArgs = @(); Explicit = $false })
      }
    }
    $pyCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCommand) {
      foreach ($selector in @("-3.14", "-3.13", "-3.12", "-3.11")) {
        $candidates.Add([pscustomobject]@{ FilePath = $pyCommand.Source; PrefixArgs = @($selector); Explicit = $false })
      }
    }
    foreach ($commandName in @("python", "python3")) {
      $pythonCommand = Get-Command $commandName -ErrorAction SilentlyContinue
      if ($pythonCommand) {
        $candidates.Add([pscustomobject]@{ FilePath = $pythonCommand.Source; PrefixArgs = @(); Explicit = $false })
      }
    }
  }

  foreach ($candidate in $candidates) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
      & $candidate.FilePath @($candidate.PrefixArgs) -c $versionProbe *> $null
      $versionExit = $LASTEXITCODE
      if ($versionExit -eq 0 -and -not $SkipDependencyProbe) {
        & $candidate.FilePath @($candidate.PrefixArgs) -c $script:SmokeDependencyProbe *> $null
        $dependencyExit = $LASTEXITCODE
      }
      elseif ($versionExit -eq 0) {
        $dependencyExit = 0
      }
      else {
        $dependencyExit = 1
      }
    }
    finally {
      $ErrorActionPreference = $previousPreference
    }

    if ($versionExit -eq 0 -and $dependencyExit -eq 0) {
      $resolved = (& $candidate.FilePath @($candidate.PrefixArgs) -c "import sys; print(sys.executable)").Trim()
      $version = (& $candidate.FilePath @($candidate.PrefixArgs) -c "import platform; print(platform.python_version())").Trim()
      Write-Host "PYTHON_RUNTIME executable=$resolved version=$version requires-python=$($requirement.Specifier)"
      return [pscustomobject]@{
        FilePath = $candidate.FilePath
        PrefixArgs = @($candidate.PrefixArgs)
        ResolvedExecutable = $resolved
        Version = $version
        RequiresPython = $requirement.Specifier
      }
    }
    if ($candidate.Explicit) {
      if ($versionExit -ne 0) {
        throw "Configured interpreter '$($candidate.FilePath)' does not satisfy requires-python '$($requirement.Specifier)'."
      }
      throw "Configured interpreter '$($candidate.FilePath)' cannot import the frozen backend runtime from .deps and backend/src."
    }
  }

  if ($SkipDependencyProbe) {
    throw "No interpreter satisfying requires-python '$($requirement.Specifier)' is available."
  }
  throw "No interpreter satisfying requires-python '$($requirement.Specifier)' can import the frozen backend runtime from .deps and backend/src. Run scripts/install-backend-deps.ps1 with the intended interpreter."
}
