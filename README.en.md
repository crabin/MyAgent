# MyAgent

Default language: [中文](README.md) | English

MyAgent is a customized fork of the PI agent project. It keeps the original PI coding-agent abilities while adding a controlled network security testing agent for defensive assessment work.

The project remains a TypeScript monorepo with the original core pieces:

- `packages/ai`: multi-provider LLM API support.
- `packages/agent`: agent runtime, state, messages, and tool calling.
- `packages/tui`: terminal UI components.
- `packages/coding-agent`: the CLI, sessions, extensions, built-in tools, and MyAgent security subagent.

## What Changed

MyAgent keeps the normal PI workflow for code reading, editing, command execution, sessions, model selection, prompt templates, skills, themes, and extensions.

On top of that, MyAgent adds a security subagent focused on authorized defensive work:

- Explicit security scope authorization before active checks.
- Passive security exploration with web research, page extraction, bounded crawl, and vulnerability lookup.
- CVE and vulnerability database normalization.
- Bounded TCP port checks and HTTP security header checks.
- Network discovery for explicitly authorized local or owned targets.
- Detection-event analysis, vulnerability assessment, and report assembly.
- Security memory for scoped notes, assumptions, and reusable defensive context.
- Guarded terminal sessions for local defensive workflows.

## Compliance

Use MyAgent only on systems, networks, applications, and data that you own or are explicitly authorized to test.

Do not use this project for illegal activity, unauthorized scanning, exploitation, persistence, credential theft, privilege escalation, lateral movement, malware activity, evasion, or disruption of third-party services. The security subagent is intended for defensive validation, learning, audit preparation, incident review, and authorized internal testing.

Active testing should always have a clear scope:

- Target assets: domains, hosts, URLs, CIDRs, or local systems.
- Allowed actions: passive research, port checks, header checks, discovery, detection analysis, reporting, etc.
- Purpose: ticket, engagement, lab exercise, internal audit, or owner-approved validation.
- Expiration: when the authorization is no longer valid.

## Install

```bash
npm install --ignore-scripts
```

For local development, use the source runner:

```bash
./pi-test.sh
```

Run checks after code changes:

```bash
npm run check
```

## Basic Usage

Start an interactive session:

```bash
./pi-test.sh
```

Run a one-shot prompt:

```bash
./pi-test.sh -p "Explain the structure of this repository"
```

List configured models:

```bash
./pi-test.sh --list-models
```

Resume a previous session:

```bash
./pi-test.sh --resume
```

Use only selected tools:

```bash
./pi-test.sh --tools read,grep,find,bash
```

## Security Usage Examples

Passive vulnerability research:

```bash
./pi-test.sh -p "Research CVE-2021-44228, summarize affected versions, impact, mitigations, and reliable references. Do not scan anything."
```

Authorized header review:

```bash
./pi-test.sh -p "I authorize defensive testing of https://example.internal for HTTP security headers only. Check the headers and produce a concise remediation report."
```

Authorized local service review:

```bash
./pi-test.sh -p "I authorize defensive testing of 127.0.0.1 on ports 3000, 5432, and 8080 for this local development machine. Check which ports are open and explain risk in plain language."
```

Detection analysis:

```bash
./pi-test.sh -p "Analyze these IDS events for likely false positives, affected assets, severity, and next investigation steps: <paste events>"
```

Assessment report:

```bash
./pi-test.sh -p "Create a defensive security assessment report from the findings in this session. Include scope, evidence, risk, and remediation."
```

## Assessment Screenshots

The screenshots below are stored in `assess/`. They show typical behavior of the MyAgent security subagent during an authorized defensive assessment.

### 1. Context And Authorization Scope

The security subagent reads the security context in the session and identifies target assets, allowed actions, purpose, and expiration. If the scope is incomplete, it asks the user to clarify before active testing.

![Context and authorization scope](assess/上下文.png)

### 2. PI Comparison: No Direct sqlmap Execution

This screenshot compares the behavior with the original PI flow. When asked to run a full sqlmap test, MyAgent does not directly execute sqlmap or provide commands that can be used for exploitation. It constrains the request to an authorized defensive scenario and offers alternatives such as checklists, validation plans, report templates, or remediation guidance.

![PI comparison: no direct sqlmap execution](assess/pi运行sqlmap.png)

### 3. Bounded Behavior After Authorization

Even after authorization is provided, the agent keeps execution bounded to the approved scope and avoids expanding targets, bypassing restrictions, or exposing unnecessary attack detail.

![Bounded behavior after authorization](assess/权限把控.png)

### 4. Single Finding Result

In an authorized lab environment, the agent turns tool output into a readable finding with target, status, method, evidence, risk, and remediation guidance.

![Single finding result](assess/结果1.png)

### 5. Consolidated Assessment Report

The agent can summarize a multi-step security review into a report covering scope, findings, evidence, risk ordering, limitations, key decisions, and next steps.

![Consolidated assessment report](assess/结果2.png)

## Development Notes

Important paths:

- `packages/coding-agent/src/core/security-subagent/`: security subagent tools and workflow logic.
- `packages/coding-agent/test/security-subagent.test.ts`: security subagent coverage.
- `packages/coding-agent/docs/`: upstream PI CLI documentation retained for existing capabilities.
- `docs/`: MyAgent-specific notes.


## Future Work

Possible future additions:

- More structured security report formats such as SARIF, JSON, Markdown, and executive summaries.
- Authenticated application security checks for owned staging environments.
- Safer scan rate limits, retry policies, and per-target budgets.
- Asset inventory import from cloud, CMDB, or internal service catalogs.
- Integration with ticketing systems for remediation tracking.
- More passive intelligence sources with source confidence scoring.
- Policy packs for common baselines such as CIS, OWASP ASVS, and internal standards.
- Better sandboxing for security terminal workflows.
- Reproducible lab profiles for training and demos.

## License

MIT
