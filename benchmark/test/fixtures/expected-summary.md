# yof benchmark

Run 123 (https://github.com/example/example/actions/runs/123), 2026-11-09. yof 0.2.0 at commit 0123456, on GitHub's ubuntu-latest runner.

Each item of an app's official list is: found (one of the yof results named for it fired), missed (yof tests this kind of problem and did not find it here; the reason was written before the run), not tested (yof does not test this kind of problem) or not available (it cannot happen in this run). Extra findings are yof results that match no item; each is reviewed by hand before publishing.

## OWASP Juice Shop v20.3.0 (commit f189f52)

Source and official list: https://github.com/juice-shop/juice-shop/tree/f189f521266f42c6bd05884468292000cee852ed, list file `data/static/challenges.yml` (24 challenges).
How it ran: The project's official Docker image of the same release, pinned by digest, on 127.0.0.1:3000 inside the runner.
Image: `bkimminich/juice-shop:v20.3.0@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`

| Result | Count |
| --- | --- |
| Found (same weakness) | 1 |
| Found (same root cause) | 4 |
| Missed | 7 |
| Not tested by yof | 6 |
| Not available in this run | 6 |
| Extra findings, not on the official list | 4 (0 false positives, 0 real, 4 to review) |

yof check: 812 files read, 160 dependencies looked up.
yof attack: 188 requests in 72 s. Groups: auth done, tenant done, rbac done, ai skipped, surface done.
OWASP Juice Shop's own score board marked these solved during yof's run: errorHandlingChallenge.

### Found

- **Admin Section** (same root cause): The administration page is hidden only in the browser. The user list it shows comes from /api/Users, which any signed-in member can read. yof: `attack.rbac_escalation GET /api/Users`
- **Vulnerable Library** (same weakness): The challenge's accepted answers are express-jwt 0.1.3 and sanitize-html 1.4.2, both pinned in package.json. yof's package check looks up exact pinned versions in the OSV advisory database. yof: `package.vulnerable package.json express-jwt@0.1.3`, `package.vulnerable package.json sanitize-html@1.4.2`
- **Unsigned JWT** (same root cause): The shop accepts a token signed with the 'none' algorithm because it pins jsonwebtoken 0.4.0 and express-jwt 0.1.3, which have published advisories for that token check. yof: `package.vulnerable package.json express-jwt@0.1.3`, `package.vulnerable package.json jsonwebtoken@0.4.0`
- **Forged Signed JWT** (same root cause): The forged token works because the pinned jsonwebtoken 0.4.0 accepts a token signed with the public key as an HMAC secret, the advisory published for versions before 4.2.2. yof: `package.vulnerable package.json express-jwt@0.1.3`, `package.vulnerable package.json jsonwebtoken@0.4.0`
- **Password Strength** (same root cause): Nothing slows down password guessing at sign-in, which is how the admin's weak password can be found by trying. yof: `attack.no_rate_limit POST /rest/user/login`

### Missed

- **Legacy Typosquatting**: The package is named only in ftp/package.json.bak, a backup file. yof reads package.json, requirements files and pyproject.toml, not backups.
- **Frontend Typosquatting**: yof flags a lookalike only when the name is one or two letters from a package on its bundled popular list. ngx-cookie, the package it imitates, is not on that list.
- **Supply Chain Attack**: eslint-scope is not pinned in a manifest yof reads; the challenge points at the forgotten backup files under ftp/.
- **View Basket**: yof's tenant test creates a record holding a marker text and reads it back as account B. A basket holds products, not text yof can mark, so the test cannot be set up for baskets.
- **Manipulate Basket**: The same limit as View Basket: yof's tenant test needs a record with a text field it can mark, and basket items have none.
- **Forged Review**: Reviews are changed with the review id in the request body. yof's tenant test needs the id in the address, so it cannot be configured for reviews.
- **Allowlist Bypass**: The shop allows a redirect when an allowed address appears anywhere in the link. yof's probe sends a plain outside address, which the shop refuses.

### Extra findings (not on the official list)

| yof result | Where | Verdict |
| --- | --- | --- |
| `attack.rbac_escalation` | `GET /api/Feedbacks` | to review |
| `attack.tenant_write` | `PUT /api/Addresss/{id}` | to review |
| `secret.private_key` | `lib/insecurity.ts:21` | to review |
| `package.vulnerable` | `package.json unzipper@0.9.15` | to review |

### Not available in this run (6)

- OWASP Juice Shop turns this off when it runs in Docker. API-only XSS.
- Needs the shop's AI chatbot, which talks to a local language-model server. The benchmark does not start one, to keep the run short, so yof's assistant probes are not run here. Chatbot Prompt Injection, Greedy Chatbot Manipulation, System Prompt Extraction, AI Debugging.
- The key is not in the shop's source code: it sits in a separate scheduled job, so no source check of this repository can find it. Leaked API Key.

### Not tested by yof (6)

- Outside what yof checks. yof looks for leaked keys and risky packages in the source, and runs five attack groups against the running app: sign-in bypass, one user reading or changing another user's records, member access to admin routes, assistant probes, and redirects, headers and sign-in limits. Bjoern's Favorite Pet, CSRF, Error Handling.
- yof finds keys by their exact shape. An email address and a password written in code have no shape it can tell apart from ordinary text. Exposed Credentials.
- yof does not read Dockerfiles or container images. Vulnerable Infrastructure.
- yof attack tests the routes its config lists. It does not search for unlisted pages such as /metrics. Exposed Metrics.

## OWASP NodeGoat commit c5cb68a

Source and official list: https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8, list file `app/views/tutorial/layout.html` (12 tutorial topics).
How it ran: Built from its own Dockerfile at the pinned commit, with MongoDB 4.4.29 (pinned by digest), on 127.0.0.1:4000 inside the runner.

| Result | Count |
| --- | --- |
| Found (same weakness) | 2 |
| Found (same root cause) | 0 |
| Missed | 4 |
| Not tested by yof | 6 |
| Not available in this run | 0 |
| Extra findings, not on the official list | 0 (0 false positives, 0 real, 0 to review) |

yof check: 120 files read, 30 dependencies looked up, 1 not answered by the registry.
yof attack: 41 requests in 20 s. Groups: auth done, tenant skipped, rbac done, ai skipped, surface done.

### Found

- **A5 Misconfig** (same weakness): The fix the app documents for this topic (server.js, "Fix for A5") adds the security headers that yof's surface group checks for. yof: `attack.missing_headers GET /`
- **A9 Insecure Components** (same weakness): Dependencies with published advisories, which yof's package check looks up for exact pinned versions. yof: `package.vulnerable package.json marked@0.3.5`

### Missed

- **A2 Broken Auth**: yof's sign-in checks need a sign-in route that answers 2xx with a token or a cookie. NodeGoat answers its sign-in with a redirect, so the benchmark signs in itself and those two checks cannot run.
- **A4 Insecure DOR**: yof's tenant test creates its own record through a JSON API and reads it back as account B. NodeGoat's pages are server-rendered forms with no such API, so the test cannot be set up.
- **A7 Access Controls**: yof compares JSON answers to decide whether a member got admin data. /benefits answers an HTML page that differs per user, so yof cannot tell the member's page from the admin's.
- **A10 Redirects**: The redirect sits behind sign-in, and yof's redirect probe runs signed out.

### Extra findings (not on the official list)

None.

### Not tested by yof (6)

- Outside what yof checks. yof looks for leaked keys and risky packages in the source, and runs five attack groups against the running app: sign-in bypass, one user reading or changing another user's records, member access to admin routes, assistant probes, and redirects, headers and sign-in limits. A1 Injection, A3 XSS, A6 Sensitive Data, A8 CSRF, ReDoS Attacks, SSRF.
