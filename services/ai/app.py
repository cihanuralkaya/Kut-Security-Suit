#!/usr/bin/env python3
"""KUT AI servisi — HTTP kablolaması (yalnız stdlib, bağımlılık yok).

handlers.py'deki saf mantığı, aibrain.HTTPProvider'ın beklediği uçlarda sunar:
  POST /v1/summarize | /v1/triage | /v1/score-sequence | /v1/score-graph | /v1/explain-risk
  GET  /health
Çalıştır:  py app.py   (adres KUT_AI_ADDR ile; vars. 127.0.0.1:8088)
Sunucuya bağlanmak için c2'yi KUT_AI_URL=http://127.0.0.1:8088 ile başlatın.

Bu bir İSKELETTİR: gerçek LLM/ML çağrısı yok (handlers.py deterministik stub). Üretimde
handlers gerçek modelle değiştirilir; sözleşme (uçlar + yanıt şekli) aynı kalır.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import handlers


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "bulunamadı"})

    def do_POST(self):
        fn = handlers.ROUTES.get(self.path)
        if fn is None:
            self._send(404, {"error": "bulunamadı"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(n) if n else b"{}"
            body = json.loads(raw or b"{}")
        except Exception:
            self._send(400, {"error": "geçersiz json"})
            return
        try:
            self._send(200, fn(body))
        except Exception as e:  # fail-safe: iskelet asla 5xx sızdırmasın
            self._send(500, {"error": "iç hata: %s" % e})

    def log_message(self, *_a):  # erişim gürültüsünü bastır
        pass


def main():
    addr = os.environ.get("KUT_AI_ADDR", "127.0.0.1:8088")
    host, _, port = addr.rpartition(":")
    srv = HTTPServer((host or "127.0.0.1", int(port or "8088")), Handler)
    print("KUT AI servisi dinliyor: %s" % addr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
