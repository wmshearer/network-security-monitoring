# Splunk Enterprise Lab — Runbook

Standing infrastructure for future portfolio projects. Installed unprivileged
(no root/sudo used or required) via the tarball distribution.

## Install summary

- Version: **10.4.2**, Build: **33c3bf42cd73**, Platform: Linux-x86_64
- Install path: `/home/kali/splunk` (NOT /opt/splunk — user-writable, no root)
- Installed/run as user: `kali` (uid=1000), no dedicated system user created
- Boot-start: NOT enabled (would require root) — start manually per below

## Exact commands used (reproducible)

```bash
# 1. Download (verified good URL as of 2026-08-21, ~1.58 GiB)
wget -O /home/kali/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz \
  "https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz"

# 2. Verify checksum (published by Splunk at the .sha512 sibling URL)
curl -s "https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz.sha512"
sha512sum /home/kali/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz
# Expected: 2e62660f31849cfac6cb4e14a7a7c98f4be3fb4e72040ef87d9674a3ba7d3857ae4e3edabc1122ba318e707dcd3d9a4ba91e5f7737776ce2e6a11fc808e11f9e
# (MATCHED on this install)

# 3. Extract (lands at /home/kali/splunk because the tarball's top-level dir is "splunk")
cd /home/kali && tar xzf splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz

# 4. First start — accepts license, seeds admin password, no interactive prompts
/home/kali/splunk/bin/splunk start --accept-license --answer-yes --no-prompt \
  --seed-passwd '<CHOOSE-A-PASSWORD>'
```

## Start / stop

```bash
/home/kali/splunk/bin/splunk start     # start splunkd + web
/home/kali/splunk/bin/splunk stop      # graceful stop
/home/kali/splunk/bin/splunk restart
/home/kali/splunk/bin/splunk status    # confirm running + PIDs
```

Boot-start (`splunk enable boot-start`) was deliberately NOT configured — it
writes a systemd/init unit and needs root. After a machine reboot, Splunk will
NOT come back on its own; re-run `splunk start` manually.

## URLs and credential

- Web UI: **http://localhost:8000** (plain HTTP, not HTTPS — confirmed: HTTPS
  probe on 8000 fails, HTTP returns 303 redirect to `/en-US/`)
- Management/REST API: **https://localhost:8089** (HTTPS, self-signed cert —
  use `curl -k` or trust the cert)
- Login: no separate account creation needed — user `admin`, password
  `<CHOOSE-A-PASSWORD>` (seeded at install time; local single-user instance, not
  suitable for anything beyond this single-user lab instance)

## License tier — ACTIVE: Trial, not Free

Verified via `splunk list licenses` and REST `/services/licenser/groups`
(`is_active: true` only on the `Trial` group entry).

- **Active group: `Trial`** (`group_id:Trial`, `subgroup_id:Production`,
  `type:download-trial`, `stack_id:download-trial`)
- **Expires: 2026-10-20** (60 days from install; `expiration_time` epoch
  1792524669)
- **Quota while on Trial: 500 MB/day** (`quota:524288000`, same cap as Free)
- Trial unlocks extra features vs. Free while active: Acceleration,
  AdvancedSearchCommands, AdvancedXML, Alerting, AllowDuplicateKeys, Auth,
  CustomRoles, DeployClient, DeployServer, DistSearch, KVStore, LDAPAuth,
  MultifactorAuth, RollingWindowAlerts, SAMLAuth, ScheduledAlerts,
  ScheduledReports, ScheduledSearch, SearchheadPooling, SplunkWeb, and more.
- **This was NOT switched to Free.** Switching is a one-way-ish operational
  decision (loses Alerting, auth features, distributed search, etc. — see the
  `Free` license-group feature list, which is much shorter) and was
  intentionally left for a deliberate decision, per instructions. To switch
  later: `splunk edit licenser-groups Free -is_active 1` (untested here).
- **On 2026-10-20 the Trial license expires.** Unless switched to Free before
  then, indexing/search will be blocked until a license action is taken.
  Put this date on a calendar.

## The 500 MB/day cap — operational hazard (applies to both Trial and Free)

- Indexing over the license quota on a given day counts as a **violation**.
- Trial policy: 5 violations in a rolling 30-day window blocks search.
- **Free policy (post-switch) is stricter: only 3 violations in 30 days blocks
  search.**
- **Splunk Free has no way to reset a violation count and no way to buy
  more headroom** — the only fix once blocked is to wait for violations to
  roll out of the 30-day window, or upgrade off Free entirely.
- Practical implication for portfolio projects: budget ingest carefully
  (500 MB/day total across ALL indexes on this instance), and treat 3
  same-day-quota-busts as a hard incident, not a warning to shrug off.

## Verification performed (2026-08-21)

- `splunk status` → `splunkd is running (PID: 2239297)`, helpers running
- Web port: `curl http://localhost:8000` → HTTP 303 → `Location: http://localhost:8000/en-US/`
  (HTTPS on 8000 fails — confirms web is plain HTTP)
- REST: `curl -k -u admin:<CHOOSE-A-PASSWORD> https://localhost:8089/services/server/info`
  → valid Atom/XML, `generator build="33c3bf42cd73" version="10.4.2"`,
  `health_info: green`
- License: confirmed Trial active as above, via both CLI and REST

## Startup warnings seen (verbatim, from splunkd.log at first start)

Expected / ignored (unprivileged install, no root available to fix):

```
WARN  ulimit - Core file generation disabled.
WARN  ulimit - This configuration of transparent hugepages is known to cause
      serious runtime problems with Splunk. [...] Please fix by setting the
      values for transparent huge pages to "madvise" or preferably "never"
      via sysctl, kernel boot parameters, or other method recommended by
      your Linux distribution.
```

THP was confirmed system-wide as `[always] madvise never` (i.e. "always" is
active) via `/sys/kernel/mm/transparent_hugepage/enabled`. Changing this
needs root — correctly left alone per constraints. Expect possible reduced
performance under memory pressure; not a functional blocker for lab use.

Also expected / cosmetic, not install-specific:

```
WARN  DC:DeploymentClient - DeploymentClient explicitly disabled through config.
WARN  HTTPAuthManager - pass4SymmKey length is too short.
WARN  SHCConfig - Default pass4symkey is being used. Please change to a random one.
WARN  SSLOptions (multiple) - server.conf sslVerifyServerCert is false [...]
WARN  X509Verify - X509 certificate [...] issued by Splunk's own default CA [...]
ERROR HttpClientRequest - Connection refused [...] localhost:8065/favicon.ico (repeated)
ERROR HttpClientRequest - Connection refused [...] localhost:5435/v1/postgres/status (repeated)
```

These are standard single-instance/default-cert warnings any fresh Splunk
install produces regardless of privilege level (self-signed cert, no SHC
pooling configured, optional Postgres-backed feature not configured). None
of these indicate a broken install.

## Undocumented questions — answered live

**REST API usable?** Yes, confirmed — `/services/server/info` returned valid
XML with version/build; `/services/data/models` returned real data model
content (sample models with fields/calculations).

**Data model acceleration available?** Ambiguous/nuanced — resolved as follows:
- The `Trial` license's `features` list explicitly includes `Acceleration`
  (from `splunk list licenses` output) — so the license does NOT block it.
- The `/services/admin/summarization` endpoint (which lists accelerated DM
  summaries) is reachable (HTTP 200, empty list — none configured yet, as
  expected on a fresh install).
- Tried to toggle acceleration two ways via REST directly on a model
  resource — both rejected as unsupported by that handler
  (`custom action 'acceleration' is not supported by this handler`;
  `Argument "acceleration.enabled" is not supported by this handler`).
- Root cause found in `datamodels.conf.spec`: acceleration is a **config file
  attribute** (`acceleration = <boolean>` in `datamodels.conf`, requires a
  Splunk restart to take effect), not a live REST PATCH field, and is
  normally toggled via the Splunk Web "Edit Acceleration" UI dialog, which
  writes that same conf setting.
- **Conclusion: acceleration is available and license-permitted on this
  instance, but was not empirically created-and-observed end-to-end** (would
  require authoring a custom data model + a datamodels.conf edit + restart,
  out of scope for infra verification). Not a blocker — just noting the
  precise mechanism for whoever builds on this next.

## Files

- Tarball: `/home/kali/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz`
- Install: `/home/kali/splunk/`
- Splunk logs: `/home/kali/splunk/var/log/splunk/splunkd.log`
- This runbook: `/home/kali/director/projects/splunk-lab/RUNBOOK.md`
- First-start console output: `/home/kali/director/projects/splunk-lab/first-start.log`
- Download log: `/home/kali/director/projects/splunk-lab/download.log`
