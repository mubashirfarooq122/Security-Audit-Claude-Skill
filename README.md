# Security Audit Claude Skill (`/code-audit`)

A [Claude Code](https://claude.com/claude-code) skill that runs an evidence-backed, read-only full code audit for **web**, **android**, and **ios** codebases.

- Four pillars: Security & Auth/Crypto · Code Quality, Concurrency, Logic & Performance · Dependencies, Config & Supply Chain · Accessibility, Privacy & Platform Compliance (incl. web SEO and Core Web Vitals causes)
- Standards: OWASP ASVS v5.0.0, OWASP Top 10 / API Top 10, WCAG 2.2 AA + WAI-ARIA, Core Web Vitals, ISO/IEC 25010, GDPR/CCPA/HIPAA, SOC 2 / ISO 27001 (web); OWASP MASVS/MASTG (MAS-L1/L2/R/P), Mobile Top 10, Google Play / Apple App Store Review, HIG, Material Design (mobile)
- Every finding cites `file:line`, exploitability/impact, a minimal patch, and a standard ID
- Findings are triaged: **Confirmed**, **Needs Runtime/Dynamic Verification**, **Out of Scope / N/A**
- Read-only: it never edits your code; fixes appear as patches in the report

## Install

Requires Claude Code.

**macOS / Linux / Git Bash**
```bash
git clone https://github.com/mubashirfarooq122/Security-Audit-Claude-Skill.git
cd Security-Audit-Claude-Skill
./install.sh              # user-level: ~/.claude/skills/code-audit
./install.sh --project    # or project-level: ./.claude/skills/code-audit (run from your project root)
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/mubashirfarooq122/Security-Audit-Claude-Skill.git
cd Security-Audit-Claude-Skill
.\install.ps1             # user-level: ~\.claude\skills\code-audit
.\install.ps1 -Project    # or project-level (run from your project root)
```

**Manual:** copy `skills/code-audit/` into `~/.claude/skills/` (all projects) or `<repo>/.claude/skills/` (one project, commit to share with your team).

Restart Claude Code after installing.

## Usage

```
/code-audit web     [target-path-or-scope] [--level=l1|l2|l3]
/code-audit android [target-path-or-scope] [--level=l1|l2|l3]
/code-audit ios     [target-path-or-scope] [--level=l1|l2|l3]
/code-audit                                  # auto-detects stack from manifests, asks if ambiguous
```

Examples:
```
/code-audit web src/api --level=l2
/code-audit android app/ --level=l1
/code-audit ios Sources/Auth --level=l3
```

Levels: `l1` baseline high-confidence issues · `l2` (default) full checklist · `l3` high assurance (adds architecture, key lifecycle, resilience, supply-chain integrity).

## Report format

1. Executive Summary & Risk Posture (counts by Critical/High/Medium/Low/Info)
2. Findings Table (ID, Severity, Variant/Category, `file:line`, Standard Ref, Summary)
3. Detailed Findings & Code Fixes (Impact, Root Cause, Evidence, Patch)
4. Verification & Next Steps (dynamic tests, MASTG/ASVS coverage, tooling, remediation order)

## Layout

```
skills/code-audit/
├── SKILL.md              # routing, workflow, hard rules
└── references/
    ├── base.md           # evidence gate, triage, severity, standards, report template
    ├── web.md
    ├── android.md
    └── ios.md
```

## Uninstall

Delete the `code-audit` folder from `~/.claude/skills/` (or your project's `.claude/skills/`).

## Notes & limitations

- Standard IDs (ASVS, MASVS, Mobile/API Top 10) are embedded from the author's knowledge; verify against the versions your organization requires. The skill is instructed to mark unverified IDs.
- This is static analysis by an LLM. It does not replace dynamic testing, SAST/SCA tooling, or a professional penetration test. Items needing runtime checks are listed explicitly in each report.

## License

MIT
