# Design Decisions

This document explains the architectural choices made in C-Sentinel, why they were made, and what trade-offs were considered. It's intended both as documentation and as a demonstration of how a systems architect approaches design.

## Why C?

**Decision**: Use C as the primary language for the system prober.

**Rationale**:
1. **Minimal dependencies**: A C binary can be deployed to virtually any UNIX system without runtime dependencies. No Python interpreter, no Node.js, no container runtime.
2. **Deterministic behaviour**: Memory allocation and deallocation are explicit. There's no garbage collector that might pause at inopportune moments.
3. **Direct system access**: We're reading `/proc`, calling `sysinfo()`, using `stat()`. C is the natural language for this.
4. **Resource efficiency**: The prober should be lightweight enough to run on production systems without impacting performance. A typical run uses <2MB RAM.

**Trade-offs accepted**:
- Longer development time compared to Python
- Manual memory management introduces potential for bugs
- JSON serialization is more tedious without native support

**Mitigations**:
- Strict coding standards (`-Wall -Wextra -Werror`)
- Use of static analysis tools (cppcheck)
- Careful buffer sizing with defined limits

## The Hybrid Architecture

**Decision**: C for the prober, Python for API communication, Flask for dashboard.

**Rationale**:
The problem naturally splits into three distinct domains:
1. **System probing**: Low-level, performance-sensitive, needs direct OS access → C
2. **API communication**: HTTP requests, JSON parsing of responses, error handling → Python
3. **Dashboard**: Web interface, database queries, real-time updates → Flask/PostgreSQL

Forcing all of this into C would mean pulling in `libcurl`, a JSON parsing library, and a web framework—adding complexity and dependencies for the API layer, the opposite of what we want for the lightweight prober.

```
┌─────────────────────────────────────────┐
│           Web Dashboard                 │
│  Flask + PostgreSQL + Chart.js          │
│  (Multi-host, charts, history)          │
└─────────────────────────────────────────┘
                    ▲
                    │ JSON via HTTP POST
                    │
┌─────────────────────────────────────────┐
│         Python Wrapper                  │
│  (LLM integration, policy engine)       │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         C Prober (76KB)                 │
│  /proc parsing, SHA256, network scan    │
└─────────────────────────────────────────┘
```

## SHA256 Checksums (v0.3.0)

**Decision**: Implement SHA256 in pure C rather than using OpenSSL or linking to system libraries.

**Rationale**:
1. **Zero dependencies**: The prober remains a self-contained binary
2. **Portability**: Works on any system without library version concerns
3. **Cryptographic integrity**: SHA256 is industry-standard, verifiable by external tools
4. **Audit-ready**: Config file checksums can be compared against known-good values

**Implementation**:
- Based on RFC 6234 / FIPS 180-4
- ~250 lines of C
- Verified against system `sha256sum` for correctness

**Previous approach**: djb2 hash (16 chars) - fast but not cryptographically secure. Replaced with full SHA256 (64 chars) for proper integrity verification.

**Trade-off**: SHA256 is slower than djb2. Acceptable—we're checksumming a handful of config files, not gigabytes of data.

## Systemd Service Design (v0.3.0)

**Decision**: Provide a production-ready systemd service unit with security hardening.

**Rationale**:
Watch mode (`--watch`) is useful for development, but production deployments need:
- Automatic restart on failure
- Clean shutdown handling
- Resource limits
- Security isolation
- Logging to journald

**Security hardening applied**:
```ini
NoNewPrivileges=yes      # Can't gain privileges via setuid
ProtectSystem=strict     # / is read-only
ProtectHome=read-only    # /home is read-only
PrivateTmp=yes           # Isolated /tmp
ReadWritePaths=/var/lib/sentinel  # Only place it can write
```

**Dedicated user**: The service runs as `sentinel` user with no home directory and `/usr/sbin/nologin` shell.

**Exit code handling**:
```ini
SuccessExitStatus=0 1 2
```

This tells systemd that exit codes 0 (OK), 1 (WARNING), and 2 (CRITICAL) are all valid results—only exit code 3 (ERROR) triggers a restart. Without this, systemd would restart the service every time it found unusual ports!

## Web Dashboard Design (v0.3.0)

**Decision**: Flask + PostgreSQL + Chart.js for multi-host monitoring.

**Rationale**:
The CLI prober is excellent for single-host diagnostics, but teams need:
- At-a-glance view of multiple hosts
- Historical trending (memory, load over time)
- Alerting when hosts go stale or critical
- Drill-down to individual host details

**Why Flask?**
- Lightweight, no magic
- Easy to deploy (gunicorn + nginx)
- Sufficient for internal tooling
- William's familiarity with Python ecosystem

**Why PostgreSQL?**
- Already running on target system (Umami)
- JSONB type for flexible fingerprint storage
- Excellent for time-series queries
- Reliable, battle-tested

**Why not Prometheus/Grafana?**
- Adds operational complexity
- Prometheus is metrics-focused, not fingerprint-focused
- We want semantic data (process lists, config checksums), not just numbers
- Building our own gives full control over the data model

**Data model**:
```sql
hosts (id, hostname, first_seen, last_seen)
fingerprints (id, host_id, captured_at, data JSONB, exit_code, ...)
```

JSONB allows storing the full fingerprint while extracting key fields (memory_percent, load_1m, etc.) into columns for efficient querying.

**Dashboard-prober communication**:
Agents POST JSON to `/api/ingest` with an API key. Simple, stateless, works through firewalls.

```bash
sentinel --json --network | curl -X POST \
  -H "X-API-Key: secret" \
  -d @- https://dashboard/api/ingest
```

## Auditd Integration Design (Planned)

**Decision**: Summarise auditd logs rather than forwarding them raw.

**Rationale**:
Security tools like auditd and AIDE answer "what happened?" with precision. C-Sentinel asks "what's weird?" The combination is powerful:

| Without auditd | With auditd |
|----------------|-------------|
| "3 unusual ports" | "3 unusual ports + 3 failed logins + /etc/shadow accessed by python script spawned from web server" |

The key insight: **context is everything**. An LLM seeing "file accessed" is one thing; seeing "file accessed by python3 spawned from apache2" is a security incident.

**Design principles**:
1. **Summarise, don't dump** - Aggregate counts, not raw logs
2. **Process ancestry** - Track the process chain (apache2 → bash → python3)
3. **Baseline deviation** - "3 failures" vs "3 failures (400% above normal)"
4. **Privacy-preserving** - Hash usernames, redact IPs in dashboard

**What we'll capture**:
- Authentication failures (count + hashed usernames + deviation from baseline)
- Sudo/privilege escalation events
- Sensitive file access with process chain
- Executions from /tmp or /dev/shm (malware indicators)
- SELinux/AppArmor denials

**What we won't capture**:
- Successful logins (noise)
- Raw usernames (privacy)
- Command arguments (could contain secrets)
- File contents (never)

See [docs/AUDIT_SPEC.md](docs/AUDIT_SPEC.md) for full specification.

## Fingerprint Design

**Decision**: Capture a "fingerprint" of system state rather than streaming metrics.

**Rationale**:
Traditional monitoring tools (Prometheus, Datadog, Dynatrace) excel at time-series metrics. They answer "what is the CPU doing right now?" C-Sentinel aims to answer a different question: "What is the overall state of this system, and what might be wrong?"

A fingerprint is:
- A point-in-time snapshot
- Comprehensive (system info, processes, configs, network)
- Structured for semantic analysis
- Suitable for diff-comparison between systems

This enables use cases that streaming metrics cannot address:
- "Compare these two 'identical' non-prod environments"
- "What's changed since last week?"
- "Given this snapshot, what do you predict will fail?"

## Network Probing Design (v0.3.0)

**Decision**: Parse `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` directly rather than using `netstat` or `ss`.

**Rationale**:
1. **No external dependencies**: `netstat` may not be installed; `ss` output format varies
2. **Deterministic parsing**: /proc files have stable, documented formats
3. **Process correlation**: We can map sockets to PIDs by scanning `/proc/[pid]/fd/`

**What we capture**:
- Listening ports (TCP/UDP, IPv4/IPv6)
- Established connections
- Owning process for each socket
- "Unusual" port detection (not in common services list)

**Common ports list**:
```c
22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
3306, 5432, 6379, 8080, 8443, 27017
```

Ports above 32768 are considered ephemeral (normal for outbound).

**Trade-off**: Process lookup for each socket is O(n×m) where n=sockets, m=processes. On systems with many connections, this could be slow. Acceptable for diagnostic use; would optimise for continuous monitoring.

## Baseline Learning (v0.3.0)

**Decision**: Store a binary "baseline" of normal system state for deviation detection.

**Rationale**:
Traditional monitoring compares metrics against static thresholds. But "normal" varies by system:
- A database server with 50 connections is normal; on a static web server, it's suspicious
- 80% memory usage might be fine for a Java app, alarming for a C daemon

Baseline learning solves this by recording what's normal *for this specific system*.

**What we track**:
| Metric | How |
|--------|-----|
| Process count | Min/max/avg range |
| Memory usage | Average and maximum |
| Load average | Maximum observed |
| Expected ports | List of ports that should be listening |
| Config checksums | SHA256 for drift detection |

**Learning vs. Comparing**:
- `--learn`: Capture current state, merge with existing baseline
- `--baseline`: Compare current state against learned baseline, report deviations

**Storage format**: Binary struct written to `~/.sentinel/baseline.dat` (user) or `/var/lib/sentinel/baseline.dat` (service)
- Magic number for validation ("SNTLBASE")
- Version field for future compatibility
- Creation and update timestamps

**Trade-off**: Binary format is not human-readable. Chose this for simplicity; could add `--baseline-export` for JSON output later.

## Configuration File (v0.3.0)

**Decision**: Support `~/.sentinel/config` with INI-style key=value format.

**Rationale**:
Users need to configure:
- API keys (Anthropic, OpenAI, Ollama)
- Thresholds (what counts as "high" memory, FDs, etc.)
- Webhook URLs for alerting
- Default behaviour (always probe network? default interval?)

**Why not YAML/JSON/TOML?**
- INI is simple to parse without external libraries
- Good enough for flat key-value configuration
- Human-readable and editable

**Path priority** (service vs user):
1. `/etc/sentinel/config` (system service)
2. `~/.sentinel/config` (user mode)
3. Environment variables (highest priority)

**Security**:
- Config file created with mode 0600 (owner read/write only)
- API keys displayed as `[set]` not actual values

## Webhook Alerting (v0.3.0)

**Decision**: Support Slack-compatible webhook format for alerts.

**Rationale**:
When running in watch mode, critical findings should notify humans immediately. Slack webhooks are:
- De facto standard (Discord, Teams, etc. accept same format)
- Simple HTTP POST with JSON payload
- No authentication complexity

**Implementation**: Shell out to `curl` rather than implementing HTTP in C.

**Trade-off**: Requires `curl` to be installed. Acceptable—it's near-universal on Linux systems.

**Alert levels**:
- Critical: Zombies, permission issues, many unusual ports
- Warning: Some unusual ports, high FD counts
- Info: Available but not implemented yet

## Exit Codes for CI/CD (v0.3.0)

**Decision**: Return meaningful exit codes for automation.

| Code | Meaning |
|------|---------|
| 0 | No issues detected |
| 1 | Warnings (minor issues) |
| 2 | Critical findings |
| 3 | Error (probe failed) |

**Rationale**:
Enables use in CI/CD pipelines:
```bash
./bin/sentinel --quick --network
if [ $? -eq 2 ]; then
    echo "Critical issues found!"
    exit 1
fi
```

## Watch Mode Design (v0.3.0)

**Decision**: Built-in continuous monitoring rather than relying on cron.

**Rationale**:
- Simpler for users: one command instead of configuring cron
- Clean shutdown handling (SIGINT/SIGTERM)
- Can accumulate worst exit code across runs
- Foundation for future features (webhooks on state change)

**Implementation**:
```c
while (keep_running) {
    run_analysis();
    sleep(interval);
}
```

**Trade-off**: Long-running process vs. cron job. For production, the systemd service with restart-on-failure is more robust.

## "Notable" Process Selection

**Decision**: Don't include all processes in the JSON output—filter to interesting ones.

A system might have 500+ processes. Sending all of them to an LLM is:
- Wasteful of tokens/cost
- Noisy (most processes are uninteresting)
- Potentially revealing (process names can leak information)

**Selection criteria**:
| Flag | Condition | Rationale |
|------|-----------|-----------|
| `zombie` | State = 'Z' | Always a problem |
| `high_fd_count` | >100 open FDs | Potential leak |
| `potentially_stuck` | State 'D' for >5 min | I/O issues |
| `very_long_running` | Running >30 days | Should probably be restarted |
| `high_memory` | RSS >1GB | Resource hog |

**Trade-off**: We might miss genuinely interesting processes that don't trigger these heuristics. Future versions could allow custom filters.

## JSON Serialization Strategy

**Decision**: Hand-rolled JSON serialization rather than using cJSON or similar.

**Rationale**:
- One fewer dependency
- Our output schema is fixed and simple
- Full control over formatting (pretty-printed for readability)
- Educational value (demonstrates string handling in C)

**Trade-offs**:
- More code to maintain
- Potential for subtle escaping bugs
- Would reconsider for more complex schemas

**Mitigation**: The `buf_append_json_string()` function handles all escaping centrally.

## Security Considerations

### Input validation
All paths and strings from external sources are length-limited. Buffer overflows are prevented by:
- Using `snprintf()` instead of `sprintf()`
- Using custom `safe_strcpy()` instead of `strcpy()`
- Defining `MAX_*` constants for all arrays

### Privilege model
The prober reads from `/proc` and specified config files. It requires:
- Read access to `/proc` (standard for all users)
- Read access to config files (may require appropriate group membership)
- **No write access anywhere** (except baseline/config in its own directory)
- **No root required** for basic operation

Some probes (like reading all process FDs) may return partial results for non-root users. This is acceptable—we document what we could probe.

### Dashboard security
- API key required for ingestion
- Sensitive audit data will require authentication (planned)
- IP addresses redacted in public views

### Sanitization
Before sending to LLM:
- IP addresses are redacted to `[REDACTED-IP]`
- Home directory paths are redacted
- Known secret environment variables are redacted
- Visible placeholders so analysts know data was present

## The Policy Engine: AI Safety Gate

**Decision**: Implement a deterministic command validator in C that sits between LLM suggestions and user presentation.

**The Problem**:
LLMs can suggest dangerous commands. Even well-intentioned suggestions like "clean up disk space" might produce `rm -rf /`. We cannot trust AI output without validation.

**Design Principles**:

1. **Deny by default in strict mode**: If we don't explicitly recognize a command as safe, require human review.

2. **No regex**: Regular expressions are a security liability (ReDoS attacks) and difficult to audit. We use simple string matching.

3. **Layered checks**: 
   - First: Check against blocked commands (rm -rf /, fork bombs, etc.)
   - Second: Check for dangerous patterns (pipes to shell, writes to /etc)
   - Third: Apply custom rules
   - Fourth: Check against safe list (in strict mode)
   - Fifth: Warn on state-modifying commands (sudo, systemctl)

4. **Audit trail**: Every decision is logged with the matched rule.

**Battle Scars Encoded**:

| Blocked Pattern | Incident Type |
|----------------|---------------|
| `rm -rf /` | The classic. Always blocked. |
| `curl\|sh` | Supply chain attack vector |
| `> /etc/passwd` | Privilege escalation |
| `--no-preserve-root` | Trying to bypass safeguards |
| `:(){:\|:&};:` | Fork bomb |
| `chmod 777 /` | Security disaster |

## Drift Detection Philosophy

**Decision**: Build fingerprint comparison as a first-class tool (`sentinel-diff`) and baseline deviation detection.

**The "Identical Systems" Lie**:
In 30 years of UNIX, I've never seen two systems that Ops claimed were "identical" actually be identical. There's always:
- A kernel parameter that got changed during debugging and never reverted
- A cron job that exists on one but not the other
- A config file that drifted after a failed deployment
- Package versions that don't match

**Why Traditional Tools Miss This**:
Monitoring tools compare each system against its own baseline. They don't compare systems against each other. If both systems have the same bug, neither alerts.

**Two Approaches**:
1. **sentinel-diff**: Compare two JSON fingerprints (different systems)
2. **--baseline**: Compare current state against learned normal (same system over time)

Both detect drift; different use cases.

## Lessons from 30 Years of UNIX

This tool embeds certain assumptions from experience:

1. **Zombies are never okay**: Some monitoring tools ignore them. We don't.
2. **Long-running processes deserve scrutiny**: A process that's been running for 30 days may have accumulated state, leaked memory, or holding stale connections.
3. **Config drift is insidious**: Two "identical" servers with one different sysctl setting have caused countless production incidents.
4. **World-writable configs are never intentional**: This is always either a mistake or a compromise.
5. **File descriptor leaks are slow killers**: The system runs fine until suddenly it doesn't.
6. **New listening ports are suspicious**: If a port wasn't open yesterday, ask why it's open today.
7. **Missing services are emergencies**: If a port was supposed to be listening and isn't, something failed.
8. **Context is everything**: "File accessed" is one thing; "file accessed by script spawned from web server" is an incident.
9. **Baselines should be learned, not configured**: What's "normal" for one system isn't normal for another.
10. **The simple approach often wins**: 76KB of C beats 100MB of dependencies.

These aren't just heuristics—they're battle scars.

---

*Last updated: January 2026*
*Author: William Murray*
