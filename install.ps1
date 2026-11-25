# Installs the /code-audit skill for Claude Code.
# Usage: .\install.ps1 [-Project]   (default: user-level ~\.claude\skills; -Project: .\.claude\skills)
param([switch]$Project)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'skills\code-audit'
if (-not (Test-Path (Join-Path $src 'SKILL.md'))) { throw "SKILL.md not found in $src" }
$dest = if ($Project) { Join-Path (Get-Location) '.claude\skills' } else { Join-Path $HOME '.claude\skills' }
New-Item -ItemType Directory -Force $dest | Out-Null
$target = Join-Path $dest 'code-audit'
if (Test-Path $target) { Remove-Item -Recurse -Force $target }
Copy-Item -Recurse $src $target
Write-Host "Installed to $target"
Write-Host "Restart Claude Code, then run: /code-audit"
