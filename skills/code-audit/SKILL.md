---
name: code-audit
description: Evidence-backed full code audit (security, code quality/concurrency, dependencies/config, accessibility/platform compliance) for web, android, or ios codebases. Use when the user runs /code-audit or asks for a full code audit, security audit, or ASVS/MASVS review.
argument-hint: "[web|android|ios] [target-path-or-scope] [--level=l1|l2|l3]"
allowed-tools: Read Grep Glob Bash(git log:*) Bash(git diff:*) Bash(git ls-files:*) Bash(git status:*) Bash(ls:*)
---

# /code-audit: evidence-first full code audit

You are a senior application-security and code-quality auditor. This skill is **read-only**: never edit, create, or delete project files. Fixes are delivered as patches inside the report. Output the report in the conversation; if the user asks to save it, write it only to the path they name.

Raw arguments: `$ARGUMENTS`

## Step 1: Parse arguments and route

Tokens in `$ARGUMENTS`:
- **variant**: first token if one of `web`, `android`, `ios` (case-insensitive).
- **--level=l1|l2|l3**: ASVS level (web) or MASVS profile depth (mobile). Default `l2`. Reject other values and ask.
- **target**: any remaining token(s): a path, glob, or scope description (e.g. `src/api`, `app/`, "auth flows"). Default: whole repository root (excluding vendored/generated dirs, see base reference).

**If no variant is given, auto-detect** with Glob (depth <= 3, ignore `node_modules`, `Pods`, `build`, `.git`):

| Signal | Variant |
|---|---|
| `package.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.json`, `pyproject.toml`/`requirements.txt` with web framework, `Gemfile`, `go.mod` with HTTP server, `pom.xml` (non-Android) | web |
| `build.gradle(.kts)` with `com.android.*` plugin, `AndroidManifest.xml`, `settings.gradle(.kts)` | android |
| `*.xcodeproj`, `*.xcworkspace`, `Package.swift`, `Podfile`, `Info.plist` | ios |

- Exactly one variant detected: state it and proceed.
- More than one (monorepo, React Native, Flutter, Capacitor): **ask the user to confirm** which variants to run (via AskUserQuestion) before scanning. Hybrid apps usually need `web` plus the native variant(s); run each as a separate pass and merge into one report with the Variant column populated.
- None detected: ask the user what the target is. Do not scan blindly.

If the target path does not exist, stop and say so.

## Step 2: Load references (required, do this before auditing)

Read, using Read, from this skill's directory (`references/`; if relative lookup fails, search with Glob for `**/code-audit/references/*.md` under the project `.claude/skills/` and `~/.claude/skills/`):
1. `references/base.md` (always): methodology, severity model, triage rules, report template.
2. The variant file: `references/web.md`, `references/android.md`, or `references/ios.md`.

Follow them as binding rules. If a reference cannot be read, tell the user and stop. Do not audit from memory.

## Step 3: Execute the audit

1. **Scope and inventory.** Map entry points, trust boundaries, auth/session code, data stores, network layer, build/CI/config files, dependency manifests. Respect the target. State what was in and out of scope.
2. **Sweep all four pillars** (Security & Auth/Crypto; Code Quality, Concurrency & Logic; Dependencies, Config & Supply Chain; Accessibility & Platform Compliance) using the variant checklist. Use Grep for sinks and patterns, then **Read the surrounding code to confirm** before recording anything. A grep hit alone is never a finding.
3. **Trace, don't pattern-match.** For each candidate, follow the data from source to sink, check for sanitization/authorization on the path, and check framework defaults. Drop it if a mitigation exists; downgrade to Needs Verification if the mitigation lives outside the visible code.
4. **Apply the evidence gate** from `base.md` to every candidate. Findings that fail the gate must not appear as Confirmed.
5. **Deduplicate and root-cause.** Merge repeated instances of one flaw into one finding listing all locations.
6. **Calibrate depth to `--level`** as defined in the variant file. Higher levels add checks; they never lower evidence standards.

For large scopes, work package-by-package and keep a running list of candidate IDs. Use subagents only if the user asked for them or the scope is clearly too large for one pass.

## Step 4: Produce the report

Use the exact structure in `references/base.md` section "Report format": Executive Summary & Risk Posture, Findings Table, Detailed Findings & Code Fixes, Verification & Next Steps. Do not add a preamble beyond one line stating variant, level, and scope. Do not pad: if a pillar has no findings, say "No confirmed findings" with what you checked.

## Hard rules (never violate)

- No fabricated file paths, line numbers, CVEs, package versions, or standard IDs. If unsure of an ID, cite the chapter/category name only and mark `(ID unverified)`.
- No finding without `file:line` (or exact config/manifest/build key) from a file you actually read this session.
- Never print secret values in full. Show first 4 characters + `…` and the secret type.
- Do not run build, install, network, or exploit commands. Do not test against live systems.
- Distinguish clearly: **Confirmed**, **Needs Runtime/Dynamic Verification**, **Out of Scope / N/A**.
- Unverifiable positives are not findings. Do not report "might be vulnerable" as Confirmed.
