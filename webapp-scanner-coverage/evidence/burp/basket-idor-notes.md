# Manual finding: basket IDOR (Broken Access Control)

Maps to Juice Shop challenge `basketAccessChallenge` ("Basket Access", category
Broken Access Control, difficulty 3) in `data/challenges.yml`.

## Setup

Two throwaway accounts registered via the REST API (`scripts/05_burp_idor_demo.py`):

- `burp-victim@example.test`, user id 31, basket id 8
- `burp-attacker@example.test`, user id 32, basket id 9

## What was done

Both requests were sent through Burp Suite Community's proxy (127.0.0.1:8080) so
they appear in Burp's own HTTP history, not just a script's stdout:

1. `GET /rest/basket/8` with the victim's own bearer token: succeeds, returns
   the victim's basket (`"UserId":31`). This is the legitimate baseline.
2. `GET /rest/basket/8` with the attacker's bearer token (decoded JWT: user id
   32, email `burp-attacker@example.test`): also succeeds, HTTP 200, and
   returns the same victim data (`"UserId":31`). Screenshot:
   `evidence/gui/burp-basket-idor.png`.

The attacker's own token is valid and correctly identifies them as user 32, but
the server never checks that basket 8 belongs to the caller. Changing one digit
in the URL path is enough.

## Why the automated scanners did not find this

Checked `evidence/zap-unauth/zap-unauth-alerts-api.json`,
`evidence/zap-auth/zap-auth-alerts-api.json`, and
`evidence/nuclei/nuclei-results.jsonl`: none contain "basket", "IDOR", or
"access control". Both ZAP runs and nuclei were structurally incapable of
raising this, not just unlucky:

- A scanner sees one HTTP response at a time. `GET /rest/basket/8` returning
  HTTP 200 with a well-formed JSON body is indistinguishable, byte for byte,
  from a legitimate request. There is no error string, no stack trace, no
  4xx/5xx status, nothing that pattern-matches against a rule.
- Finding this requires a second identity to compare against: the scanner
  would have to authenticate as two different users, request the same
  resource ID as each, and notice that "UserId" in the response does not
  match the caller. ZAP's active scan rules operate against one authenticated
  session at a time (whichever identity replaced the Authorization header via
  the replacer rule) and never cross-reference two identities against the
  same resource.
- Nuclei matches request/response templates against known signatures. There
  is no generic signature for "this number belongs to a different account
  than the one that asked for it", because that depends on the application's
  own data model, not on any string or header a template can match.

This is the mechanism behind the Broken Access Control gap in FINDINGS.md, not
just an example of it.
