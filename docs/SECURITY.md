# Security

## Reporting

Open a [security advisory](https://github.com/Arafat-debug765/AI-Cyber-Threat-detector/security/advisories/new)
rather than a public issue. This is a personal project with no SLA; expect
best-effort.

## Deployment posture

This tool analyses your network's traffic. Its output — who talks to whom, on
which ports, in what volume — is exactly the reconnaissance an attacker wants.
Treat the service as sensitive infrastructure, not a dashboard.

**Minimum safe configuration**

| Setting | Why |
|---|---|
| `API_TOKEN` set to 32+ random bytes | Without it, anyone who reaches the port reads the analysis and can start training runs. `serve` refuses a non-loopback bind without one. |
| Bind `127.0.0.1`, or put a TLS reverse proxy in front | There is no transport security here; a bearer token over plain HTTP on a LAN is a token you have given away. |
| `ALLOWED_HOSTS` listing only the names you serve | Blocks DNS rebinding. `*` disables the check. |
| `MODEL_KEY_FILE` outside the model directory | A signature is worthless if whatever can write the model can read the key. |
| Run as a non-root user | The app never needs privileges. Only live capture does, and that is a separate script. |

`FLASK_DEBUG` must stay off anywhere reachable: the Werkzeug debugger is remote
code execution by design.

## Findings register

Everything found in review, and what was done. Severity is the impact on an
operator running this as intended.

### Fixed

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | **High** | `joblib.load` unpickles the model, executing whatever the file contains. An attacker able to write `models/model.pkl` had code execution. | HMAC-SHA256 verified before any unpickling (`integrity.py`). |
| 2 | **High** | The signing key was generated *inside* the model directory, so anything that could write the model could usually read the key that authenticated it. | Key defaults to `.secrets/`, configurable via `MODEL_KEY_FILE`; env-provided keys never touch disk. Existing keys are adopted, not invalidated. |
| 3 | **High** | No authentication on any endpoint. The full traffic analysis was readable, and training startable, by anyone who could reach the port. | `API_TOKEN` gates `/api/*`; constant-time comparison; `serve` refuses a routable bind without one. |
| 4 | **High** | Cross-site request forgery: any page the operator visited could `POST /api/train` to their local instance. | State-changing requests must carry `X-Requested-With: threat-detector`, which forces a CORS preflight a hostile origin cannot satisfy. |
| 5 | **Medium** | DNS rebinding: a hostile domain could be pointed at the loopback port and read responses. | `Host` header allowlist (`ALLOWED_HOSTS`). |
| 6 | **Medium** | Stored XSS path — packet fields (attacker-influenced) were concatenated into `innerHTML`. | All rendering via `textContent` / `createElementNS`, plus a CSP with `script-src 'self'`. |
| 7 | **Medium** | Error responses returned absolute filesystem paths, disclosing the host account name and layout. | Paths relativised (`_public_path`); tests assert no absolute paths in responses. |
| 8 | **Medium** | Unbounded request bodies were accepted and ignored — Flask only enforces `MAX_CONTENT_LENGTH` when something reads the body. | `Content-Length` checked explicitly before buffering. |
| 9 | **Medium** | Model and signature were two separate files, so a crash or a concurrent reader between the writes left a new model against an old signature — the app refused to start until a full retrain. | Signature lives inside the model file; one `os.replace`, which is atomic. |
| 10 | **Medium** | Overlapping training runs raced onto the same model file. | Single-flight background jobs with state on disk. |
| 11 | **Medium** | Synchronous training blocked the worker for the whole fit; any capture worth analysing timed out the request. | `POST /api/train` returns 202; progress polled via `/api/status`. |
| 12 | **Medium** | A model fitted on 300-second sessions would happily score 60-second sessions — confident nonsense, no error. | `load_model` refuses a bundle whose `feature_set`, `algorithm` or `window_seconds` disagrees with the running config. |
| 13 | **Medium** | Alert threshold was calibrated at the minimum baseline score, so a single one-packet capture-boundary artifact set the bar and hid a 200-host sweep beneath it. | `MIN_SESSION_PACKETS` drops windows too small to be behaviour. Detection went from 2 of 4 attacks to 4 of 4. |
| 14 | Low | `scripts/inspect_model.py` crashed against the current model format and loaded it without verifying the signature. | Replaced by `threat-detector inspect`, which goes through the verified loader. |
| 15 | Low | A catch-all handler turned ordinary 404s and 405s into 500s. | `HTTPException` handled above the catch-all. |
| 16 | Low | No `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, or CSP. | Set on every response. |

### Accepted, with reasons

| Finding | Why it stands |
|---|---|
| A poisoned baseline defeats detection entirely | Inherent to unsupervised baselining. The system cannot verify the operator's assertion that a capture is clean. Documented, not hidden. |
| No rate limiting | Deployment concern; belongs in the reverse proxy, not duplicated here. |
| No TLS | Same — terminate at a proxy. Shipping a half-configured TLS stack would be worse. |
| The whole capture is held in memory | A streaming rewrite is a large change for a tool that runs offline on bounded captures. The limit is documented rather than pretended away. |
| Unauthenticated by default on loopback | A first run must work. The refusal to bind elsewhere without a token is what makes this safe. |

### Known gaps, not yet addressed

| Gap | Impact |
|---|---|
| No audit log of who queried what | On a multi-operator install you cannot reconstruct who pulled the analysis. |
| Beacon detection depends on window alignment | A beacon whose period is close to `WINDOW_SECONDS` may be missed. A periodicity feature over a longer horizon would fix it properly. |
| No IPv6 | IPv4-only, and IPv6 packets are silently skipped at ingest. On a dual-stack network that is a blind spot. |
| Model files are still pickles | Signing makes them safe to *reload*, not safe to *share*. Never load a model someone sent you. |
