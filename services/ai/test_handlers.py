"""KUT AI servisi testleri — yalnız stdlib (unittest + urllib). Saf mantığı ve HTTP
kablolamasını doğrular; aibrain.HTTPProvider sözleşmesine (yanıt şekilleri) uyumu kontrol
eder. Çalıştır:  py -m unittest  (services/ai/ dizininde)."""
import json
import threading
import unittest
import urllib.request
from http.server import HTTPServer

import app
import handlers


class TestPureLogic(unittest.TestCase):
    def test_triage_priority_and_shape(self):
        low = handlers.triage({})
        self.assertEqual(low["priority"], "LOW")
        self.assertTrue(low["likely_fp"])
        hi = handlers.triage({"Signals": [1, 2, 3], "Events": ["a", "b"]})
        self.assertEqual(hi["priority"], "CRITICAL")
        self.assertFalse(hi["likely_fp"])
        for k in ("priority", "likely_fp", "next_steps", "confidence", "source"):
            self.assertIn(k, hi)

    def test_score_graph_features_only(self):
        r = handlers.score_graph({"features": {"FanOut": 3, "FanIn": 1, "RareEdges": 2}})
        self.assertEqual(r["score"], 3 * 5 + 1 * 3 + 2 * 8)  # 34
        for k in ("score", "rationale", "source"):
            self.assertIn(k, r)

    def test_score_sequence(self):
        self.assertEqual(handlers.score_sequence({"Tokens": ["a", "b"]})["score"], 24.0)

    def test_summarize_and_explain(self):
        self.assertIn("pc-1", handlers.summarize({"Device": "pc-1", "Events": ["e"]})["text"])
        self.assertIn("88", handlers.explain_risk({"Score": 88})["text"])

    def test_routes_cover_contract(self):
        for p in ("/v1/summarize", "/v1/triage", "/v1/score-sequence", "/v1/score-graph", "/v1/explain-risk"):
            self.assertIn(p, handlers.ROUTES)


class TestHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), app.Handler)  # efemeral port
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _post(self, path, body):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())

    def test_triage_endpoint(self):
        code, out = self._post("/v1/triage", {"Signals": [1, 2, 3], "Events": ["a", "b"]})
        self.assertEqual(code, 200)
        self.assertEqual(out["priority"], "CRITICAL")

    def test_health(self):
        with urllib.request.urlopen("http://127.0.0.1:%d/health" % self.port, timeout=5) as r:
            self.assertEqual(r.status, 200)


if __name__ == "__main__":
    unittest.main()
