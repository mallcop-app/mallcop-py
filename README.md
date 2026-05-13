> [!IMPORTANT]
> **This Python implementation of mallcop has been superseded by the Go version.**
>
> - Active development: [github.com/mallcop-app/mallcop](https://github.com/mallcop-app/mallcop) (Go)
> - Connectors: [github.com/mallcop-app/mallcop-connectors](https://github.com/mallcop-app/mallcop-connectors)
> - This package (`mallcop` on PyPI) is in maintenance mode at 0.5.x — only security fixes will be applied.
> - The Go version drops these Python connectors: `container_logs`, `supabase`, `vercel`, `openclaw_config_drift`. Operators depending on those should stay on 0.5.x or contribute Go ports upstream.
> - License changes from Apache-2.0 (this repo) to MIT (Go repo).

# mallcop

Security monitoring for small cloud operators. AI-native. Self-hosted. Near-$0.

## What is this?

Mallcop watches your cloud infrastructure and tells you when something's wrong. It's designed for AI agents to operate -- not humans clicking dashboards.

Think of it as the security guard at your mall. Not a SWAT team. Just someone who knows the building, notices when something's off, and calls you when it matters.

## Who is it for?

- Solo founders running cloud services
- Small teams too small for a SIEM, too exposed for nothing
- AI agents operating infrastructure that need security awareness

## What does it monitor?

8 connectors, 12 detectors, 9 domain skills, 6 actors, 56 Academy Exam scenarios. 2664 tests.

### Connectors

| Connector | What it watches |
|-----------|----------------|
| **Azure** | Activity log, container apps, resource modifications, Defender alerts |
| **AWS CloudTrail** | IAM changes, security group modifications, console logins, S3 policy changes |
| **GitHub** | Repo changes, permission changes, security alerts, Actions |
| **Microsoft 365** | Sign-ins, admin actions, email events |
| **Vercel** | Deployments, audit log, team membership changes |
| **Container Logs** | Container app stdout/stderr via Log Analytics |
| **Supabase** | Auth audit logs, Management API config monitoring |
| **OpenClaw** | Skill integrity, config drift, gateway security (via ClawCop) |

### Detectors

| Detector | What it catches |
|----------|----------------|
| **priv-escalation** | Role grants, permission changes, self-elevation |
| **unusual-timing** | Activity outside established patterns |
| **auth-failure-burst** | Brute force and credential stuffing |
| **volume-anomaly** | Unusual event volume spikes |
| **new-actor** | Previously unseen identities |
| **new-external-access** | External access from new sources |
| **unusual-resource-access** | Known actors touching new resources |
| **injection-probe** | Prompt injection attempts in event data |
| **log-format-drift** | Container log format changes (parser degradation) |
| **git-oops** | Leaked credentials in git repos |
| **malicious-skill** | Encoded payloads, quarantine bypass, known-bad authors in OpenClaw skills |
| **openclaw-config-drift** | Auth disabled, plaintext secrets, mDNS broadcasting |

### Domain Skills

9 SSH-signed investigation skills with a PKI trust web. Skills provide domain-specific reasoning that investigation actors load on demand.

| Skill | Domain |
|-------|--------|
| **privilege-analysis** | General privilege escalation reasoning (parent skill) |
| **aws-iam** | IAM trust policies, AssumeRole chains, SCPs |
| **azure-security** | Azure RBAC, Activity Log, Container Apps, Defender |
| **github-security** | Repository permissions, Actions, deploy keys |
| **supabase-security** | Auth policies, RLS, Management API |
| **container-logs-security** | Log analysis, crash patterns, log injection |
| **openclaw-security** | Malicious skill detection, ClawHavoc IOCs |
| **m365-security** | Sign-in analysis, admin operations |
| **vercel-security** | Deployment security, team access |

Skills are signed with SSH keys and verified against a trust web (anchors, endorsements, BFS trust chain). `skills.lock` pins content hashes. Unsigned or tampered skills are refused.

### Actors

| Actor | Role |
|-------|------|
| **triage** | Level-1: quick severity assessment, resolve or escalate |
| **investigate** | Level-2: deep investigation with tools, skills, and baseline cross-reference |
| **heal** | Auto-remediation for parser drift and config issues |
| **notify-teams** | Microsoft Teams webhook notifications |
| **notify-slack** | Slack Block Kit notifications |
| **notify-email** | HTML digest email via SMTP |

### ClawCop — OpenClaw Security Monitor

Mallcop watches your cloud. ClawCop watches your AI agent.

ClawCop is mallcop's built-in OpenClaw security capability. Add the `openclaw` connector to your `mallcop.yaml` and it works through the standard scan/detect/escalate pipeline.

It catches malicious skills, config drift, and skill lifecycle changes. No API credentials required -- reads directly from `~/.openclaw/`. See [docs/clawcop.md](docs/clawcop.md) for details.

### Academy Exam

56 adversarial scenarios that test mallcop's investigation quality. Each scenario presents a security finding with a trap -- a deceptive element designed to exploit common reasoning failures (admin exemption, known-actor bias, context switching).

```bash
mallcop exam run                    # run all scenarios
mallcop exam run --tag AE           # run admin-exemption scenarios only
mallcop exam run --scenario PE-01   # run one specific scenario
mallcop improve --from-exam results.json  # analyze failures, suggest fixes
```

Graded by an LLM judge on reasoning quality, investigation thoroughness, and actionability. Not pass/fail on the action -- pass/fail on whether the investigation was rigorous.

### Entity Reputation

Tracks per-entity trust scores across all connectors. Findings decrement scores by severity. Baseline matches reward scores. Scores decay toward neutral with a 30-day half-life.

## Install

```bash
pip install mallcop
```

## Quickstart

### 1. Initialize

```bash
mkdir my-security && cd my-security
git init
mallcop init
```

`mallcop init` discovers your environment -- probes for Azure subscriptions, GitHub orgs, and other connected platforms. It writes a `mallcop.yaml` config file and reports estimated costs.

All output is JSON by default (for AI agents). Use `--human` for readable output on any command.

### 2. First scan

```bash
mallcop scan
mallcop detect
```

`mallcop scan` polls all configured connectors and stores events in `events/` as JSONL files.

`mallcop detect` runs detectors against stored events and writes findings to `findings.jsonl`.

During the first 14 days (the baseline learning period), detectors log findings as informational only -- no escalation, no alerts. This lets mallcop learn what "normal" looks like for your environment.

### 3. Automated monitoring

```bash
mallcop watch              # scan + detect + escalate
mallcop watch --dry-run    # skip actor escalation
```

### 4. Set up scheduled runs

The recommended setup is a GitHub Actions workflow that runs every 6 hours:

```yaml
name: mallcop-watch
on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install mallcop
      - run: mallcop watch
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      - run: |
          git config user.name "mallcop"
          git config user.email "mallcop@noreply"
          git add -A
          git diff --cached --quiet || git commit -m "mallcop watch $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push
```

### 5. Investigation

```bash
mallcop review                      # orient: all open findings + context
mallcop investigate <finding-id>    # deep investigation with tools + skills
mallcop events --finding <id>       # query events
mallcop baseline --actor <actor>    # check baseline for an actor
mallcop report --status open --severity warn,critical
```

### 6. Skill and trust management

```bash
mallcop skill list                  # show installed skills
mallcop skill sign <dir> --key <keyfile>   # sign a skill directory
mallcop skill verify <dir>          # verify skill signature
mallcop skill lock                  # regenerate skills.lock
mallcop trust add-anchor <id> <pubkey>     # add trust anchor
mallcop trust endorse <id> --scope "aws-*" --level author --key <keyfile>
mallcop trust chain <identity>      # show trust path
mallcop trust list                  # show trust web
```

## CLI commands

```
# Core pipeline
mallcop init                        # discover environment, write config
mallcop scan                        # poll all connectors, store events
mallcop detect                      # run detectors against events
mallcop escalate                    # invoke actor chain on open findings
mallcop watch [--dry-run]           # scan + detect + escalate

# Investigation
mallcop review                      # POST.md + all open findings + commands
mallcop investigate <finding-id>    # deep context for one finding
mallcop finding <finding-id>        # finding detail + annotation trail
mallcop events [--finding] [--actor] [--source] [--hours] [--type]
mallcop report [--status] [--severity] [--since]
mallcop baseline [--actor] [--entity]
mallcop status [--costs]            # operational status and cost trends

# Finding management
mallcop annotate <finding-id> <text>
mallcop ack <finding-id> [--reason]

# Skills and trust
mallcop skill list | sign | verify | lock
mallcop trust add-anchor | add-key | endorse | chain | list

# Quality
mallcop exam run [--tag] [--scenario] [--model]
mallcop improve [--from-exam <file>] [--refresh-patterns]

# Development
mallcop scaffold <type> <name>
mallcop verify [--all]
mallcop discover-app <app-name>
```

All commands output JSON by default. Use `--human` for readable output.

## Deployment repo structure

```
my-security/
  mallcop.yaml              # config: connectors, routing, secrets, budget
  checkpoints.yaml          # connector cursors (last poll position)
  events/                   # append-only JSONL, partitioned by source and month
    azure-2026-03.jsonl
    github-2026-03.jsonl
  findings.jsonl            # detector output
  costs.jsonl               # per-run token usage and cost tracking
  baseline.json             # known actors, frequency tables, relationships
  reputation.jsonl          # per-entity trust scores
  skills.lock               # skill content hash pins
```

Everything is git-tracked. `git log events/` shows when events were ingested. `git diff findings.jsonl` shows what changed between runs.

## Cost

Near-$0. Mallcop is free and open source. The platform APIs it monitors are free tier. The only cost is LLM inference for the triage/investigate actors during escalation, controlled by configurable budget limits (default: 50k tokens/run). `mallcop init` estimates your steady-state costs based on discovered resources.

## License

Apache 2.0
