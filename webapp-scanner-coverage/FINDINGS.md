# Findings

Every number below traces to a file in `evidence/`. None are recomputed by
hand; the scoring numbers come straight from `scripts/06_score_alerts.py`.

## 1. The manifest (ground truth)

`data/challenges.yml` is Juice Shop's own list of every vulnerability it
contains, one entry per challenge, with a `name`, `category`, `difficulty`,
and unique `key`.

- Parsed by `scripts/01_parse_manifest.py`.
- Output: `evidence/manifest/challenges_table.csv` (116 rows) and
  `evidence/manifest/category_counts.csv` (16 categories).
- Top counts: Sensitive Data Exposure 17, Injection 14, Improper Input
  Validation 12, Broken Access Control 12, XSS 9, Vulnerable Components 9.
  Confirmed by `tests/test_manifest.py::test_top_category_counts_match_ground_truth`.

## 2. Unauthenticated ZAP scan

Target: `http://127.0.0.1:3000` only. ZAP 2.17.0, Automation Framework plan
(`scripts/zap-plans/unauth-plan.yaml`): spider, then passive scan, then
active scan (max 8 minutes).

- Spider found 101 URLs (`evidence/zap-unauth/zap-unauth-report.html`).
- Active scan raised **5 distinct alert types across 283 alert instances**:
  Content Security Policy (CSP) Header Not Set, Cross-Domain Misconfiguration,
  Timestamp Disclosure - Unix, Modern Web Application, User Agent Fuzzer.
  Source: `evidence/zap-unauth/zap-unauth-alerts-api.json`, pulled from ZAP's
  own REST API rather than the report file (see tool failure below).
- Real GUI capture: `evidence/gui/zap-unauth-alerts.png`, taken after the
  active scan reached 100%, showing the Sites tree with the target and the
  Alerts tab listing all 5 alert types.

**Tool failure to record:** the traditional-json report template threw a
`TemplateProcessingException` on `helper.isSystemic(alert)` and produced a
truncated file (confirmed: `python3 -m json.tool` on it fails at line 205).
Eight built-in passive-scan scripts (Application Error Scanner, Base64
Disclosure, Debug Error Disclosure, Email Disclosure, PII Disclosure, Private
IP Disclosure, Username Idor Scanner, XML Comments Disclosure) also errored
with `Could not find option with name js.ecmascript-version` and did not run
at all in this ZAP install. This means the unauthenticated result understates
what a working install of those 8 rules might have found; it is not evidence
that Juice Shop has none of those issues. The HTML report and the live API
both agree with each other and are what this project's numbers are built
from.

## 3. Authenticated ZAP scan

A throwaway account was registered and logged in via Juice Shop's own REST
API (`scripts/02_register_and_login.py`), then the resulting JWT was injected
as a bearer token on every request using a ZAP replacer rule
(`scripts/04_run_zap_auth.py`, `scripts/zap-plans/auth-plan-template.yaml`),
so the spider and active scan ran as a logged-in user instead of an anonymous
visitor.

- Spider found **66 URLs**, fewer than the 101 found unauthenticated
  (`evidence/zap-auth/zap-auth-spider-urls.json`). Not explained further here;
  flagged as a real, measured difference worth investigating separately
  (possible cause: some anonymous-only routes, like the login/registration
  forms themselves, may render less linked content once already logged in).
- Active scan raised the **same 5 alert types, same 283 instances**, as the
  unauthenticated run. Source: `evidence/zap-auth/zap-auth-alerts-api.json`.
  Confirmed identical by
  `tests/test_scoring.py::test_zap_auth_and_unauth_same_alert_types`.
- **The authenticated versus unauthenticated delta is zero** for automated
  active-scan findings. Logging in did not surface anything new.
- Real evidence of the authenticated crawl actually running as a logged-in
  user: `evidence/gui/zap-auth-websockets.png` shows a genuine Juice Shop
  `"challenge solved"` socket.io message (`passwordRepeatChallenge`) fired
  during the crawl, meaning the authenticated session was exercising real
  app functionality, not just hitting public pages with an extra header.

**GUI capture problem to record:** partway through this session, ZAP's tab
bar in the running GUI window stopped accepting `xdotool` clicks entirely
(the Alerts tab, the Sites-tree disclosure triangle, and even a working
click recipe from the earlier unauthenticated capture all failed to switch
tabs), while the window remained genuinely active and the API on the same
process kept returning live data. Root cause not identified. The WebSockets
tab, already selected when this started, was captured instead, which is why
the authenticated evidence is a WebSocket screenshot plus API-sourced alert
JSON rather than an Alerts-tab screenshot like the unauthenticated run has.

## 4. nuclei scan

nuclei v3.11.1 (confirmed via `nuclei -version`), templates updated to
**v10.4.8** via `-update-templates` (the task brief said v10.4.6; that was
the version before the update ran, recorded here rather than silently
corrected). 10,730 templates loaded, single run against
`http://127.0.0.1:3000` (`scripts/03_run_nuclei.sh`).

- **19 matches** in `evidence/nuclei/nuclei-results.jsonl`: a Swagger/OpenAPI
  doc, robots.txt (matched twice by two different templates), security.txt,
  8 instances of missing security headers, DOM/tech fingerprinting (4
  templates), an `X-Recruiting` header, and one medium-severity finding: an
  exposed Prometheus `/metrics` endpoint.
- Scan completed cleanly: "Scan completed in 5m. 19 matches found."
  (`evidence/nuclei/nuclei-run.log`). 83 request errors out of 18,668 sent,
  which is normal for a broad template set run against one small app (most
  errors are timeouts on templates probing technology Juice Shop does not
  run, for example specific CMS or database admin panels).

## 5. Manual finding: basket IDOR via Burp Proxy

Burp Suite Community edition has no automated scanner. This is confirmed
directly from PortSwigger's own edition comparison, which lists "Scanner" as
a Professional/Enterprise-only feature and does not list it under Community.
This project therefore used Burp's Proxy and its request/response viewer
manually, not an automated Burp scan, and frames the comparison as automated
scanning versus manual testing rather than "Burp versus ZAP," since the
editions are not comparable tools.

Two throwaway accounts were created (`scripts/05_burp_idor_demo.py`):
`burp-victim@example.test` (user id 31, basket id 8) and
`burp-attacker@example.test` (user id 32, basket id 9). Both a legitimate
request (victim reading their own basket) and the test request (attacker
reading the victim's basket) were sent through Burp's proxy on
`127.0.0.1:8080` so they appear in Burp's own HTTP history.

**Result:** `GET /rest/basket/8` with the attacker's own valid bearer token
returns HTTP 200 with the victim's data (`"UserId":31`), identical to what
the victim's own token returns. Full detail and the decoded JWT proving which
token was used: `evidence/burp/basket-idor-notes.md`. Screenshot of the real
Burp request/response panes: `evidence/gui/burp-basket-idor.png`.

This maps exactly to Juice Shop's `basketAccessChallenge` ("View Basket":
"View another user's shopping basket.", category Broken Access Control,
difficulty 2).

## 6. Scoring: what the coverage table means

`scripts/06_score_alerts.py` maps each real finding above to a challenge key
only where the finding's own description matches what the challenge actually
asks for, never a loose category guess. The full mapping, including every
real finding that did NOT match a scored challenge and why, is in
`evidence/scoring/alert_mapping.csv`.

**Result: 1 of 116 challenges found by an automated scanner (Exposed
Metrics, Observability Failures), 1 more found only by manual testing
(View Basket, Broken Access Control), 114 found by neither.**
(`evidence/scoring/coverage_by_category.csv`,
`tests/test_scoring.py::test_coverage_totals_match_manifest`.)

Findings that were real but did not map to any scored challenge, and why:

- **CSP header missing** (ZAP): no manifest challenge asks for a missing CSP
  header. The closest entry, "CSP Bypass" (XSS), assumes a CSP already exists
  and asks to get around it, which is a different flaw.
- **Cross-Domain Misconfiguration / CORS** (ZAP): no manifest challenge
  matches this exact server configuration.
- **Timestamp Disclosure** (ZAP): no manifest challenge asks for this.
- **Swagger/OpenAPI doc exposed** (nuclei): no manifest challenge asks for
  this.
- **security.txt found** (nuclei): the "Security Advisory" challenge
  (`csafChallenge`, Miscellaneous) hints that advisories are "often listed in
  the security.txt", but solving it requires finding a specific CVE checksum
  and reporting it, not just detecting that the file exists. Counting a file
  detection as solving this challenge would overstate coverage.
- **X-Recruiting header found** (nuclei): the closest manifest entry, "Login
  Support Team" (Security Misconfiguration), requires finding leaked support
  team credentials through a different mechanism (a human-error story about
  low-cost outsourcing, per its own hints), not reading this header. Counting
  it would overstate coverage.
- Missing security headers, DOM/tech fingerprinting, robots.txt: none map to
  a specific scored challenge.

This conservative approach means the 1-in-116 number is a floor, not a
generous estimate: several real, correct scanner findings above were left
uncounted specifically because forcing them into a category would have
made the coverage number look better than what was actually demonstrated.

## 7. What the numbers show about the mechanism

Both ZAP scans (unauthenticated and authenticated) and nuclei operate on one
HTTP request and one response at a time, evaluated against a fixed rule or
template. That design finds:

- Missing headers and misconfigurations (CSP, CORS): present in every
  response regardless of who is asking. Both scanners found several of
  these.
- An exposed endpoint at a guessable, well-known path (`/metrics`): nuclei's
  template list already had the exact path to check. This is the one
  confirmed hit against the manifest.

That same design cannot find **Broken Access Control**, where 11 of 12
manifest challenges went unfound by any tool here. A request like
`GET /rest/basket/8` returning HTTP 200 with a normal-looking JSON body is
not distinguishable, on its own, from a correct response. The only way to
tell it is wrong is to already know who is allowed to see basket 8, compare
that against who is actually asking, and notice they do not match. That
comparison needs two identities and a notion of ownership that is specific
to this application's own data model. Neither ZAP's active scan rules nor
nuclei's templates carry that context; they are built to be reusable across
any target, and "who owns this specific record" is never a property a
reusable rule can encode. This is why authenticating the scanner (running it
as a logged-in user) did not close the gap either: an authenticated scan is
still one identity crawling one session, so it can find pages a login is
required to reach, but it still has no second identity to compare against.
The manual test in this project only worked because it set up two accounts
on purpose and checked one against the other, a step no automated rule in
either tool takes on its own.

## Uncertainties and things not verified further

- Why the authenticated spider found fewer URLs (66) than the unauthenticated
  one (101) was not investigated beyond noting it. It could be a real
  behavior difference (some routes exist only for anonymous visitors) or an
  artifact of how ZAP's spider handles the injected Authorization header on
  URLs that do not need it. Flagged, not resolved.
- The 8 broken ZAP passive-scan scripts mean this project cannot say Juice
  Shop has zero findings in those specific rule categories (Base64
  Disclosure, Debug Error Disclosure, Email Disclosure, PII Disclosure,
  Private IP Disclosure, Username Idor Scanner, XML Comments Disclosure,
  Application Error Scanner), only that this ZAP install could not check for
  them in this run.
- Coverage against 116 challenges assumes a scanner alert is only a "find" if
  it maps to a specific challenge's stated objective. A more generous scoring
  rule (crediting any real finding in the right general category) would raise
  the number; that rule was rejected here because it would count things like
  "a Swagger doc exists" as solving a challenge that actually requires
  reporting a specific vulnerable library version, which is not the same
  accomplishment.
