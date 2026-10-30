"""Local stand-in for the embedding API. Hashed bag-of-words: tests plumbing only, NOT model quality."""
import hashlib
import http.server
import json
import math
import re
import threading


def _stub_vector(text: str, dims: int = 2048) -> list[float]:
    v = [0.0] * dims
    for w in re.findall(r"[a-z0-9]{3,}", text.lower()):
        w = re.sub(r"(ing|ed|es|s)$", "", w)
        v[int(hashlib.md5(w.encode()).hexdigest(), 16) % dims] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def start_stub() -> str:
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            data = [{"index": i, "embedding": _stub_vector(t)} for i, t in enumerate(body["input"])]
            raw = json.dumps({"data": data}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(raw)

        def log_message(self, *a):  # silence
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/v1"
