"""AnthropicBackend against a local fake Messages API (real SDK, no network, no key)."""

import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import anthropic

from blockswarm.config import InferenceConfig
from blockswarm.harness import AgentContext, AgentHarness
from blockswarm.inference import (AnthropicBackend, InferenceError, ServiceUnavailable,
                                  make_backend)
from blockswarm.tasks import KINDS


class FakeAPI:
    def __init__(self):
        self.requests = []
        self.reply = {"text": '{"label": "positive", "confidence": 0.9}', "stop_reason": "end_turn",
                      "status": 200}
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                api.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                r = api.reply
                if r["status"] != 200:
                    payload = {"type": "error", "error": {"type": "invalid_request_error",
                                                          "message": "bad"}}
                else:
                    payload = {
                        "id": "msg_1", "type": "message", "role": "assistant",
                        "model": body["model"], "stop_sequence": None,
                        "content": [{"type": "text", "text": r["text"]}],
                        "stop_reason": r["stop_reason"],
                        "stop_details": ({"type": "refusal", "category": "cyber", "explanation": "x"}
                                         if r["stop_reason"] == "refusal" else None),
                        "usage": {"input_tokens": 42, "output_tokens": 7},
                    }
                data = json.dumps(payload).encode()
                self.send_response(r["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                api.requests.append({"path": self.path, "headers": dict(self.headers), "body": None})
                ok = self.path.endswith("/claude-opus-5-5")
                payload = ({"type": "model", "id": "claude-opus-5-5", "display_name": "Claude Opus 5.5",
                            "created_at": "2026-01-01T00:00:00Z"} if ok else
                           {"type": "error", "error": {"type": "not_found_error", "message": "nope"}})
                data = json.dumps(payload).encode()
                self.send_response(200 if ok and api.reply["status"] == 200 else
                                   (api.reply["status"] if ok else 404))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class AnthropicBackendTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.addCleanup(self.api.close)
        self.cfg = InferenceConfig()
        client = anthropic.Anthropic(api_key="test-key", base_url=self.api.url, max_retries=0)
        self.backend = AnthropicBackend(self.cfg, client=client)
        self.messages = [{"role": "system", "content": "TASK_KIND: classify_sentiment\nBe brief."},
                         {"role": "user", "content": 'Input:\n{"text": "great"}'}]

    def test_defaults(self):
        self.assertEqual(self.cfg.backend, "anthropic")
        self.assertEqual(self.cfg.model, "claude-opus-5-5")
        self.assertFalse(self.backend.is_mock)

    def test_request_shape(self):
        schema = KINDS["classify_sentiment"].output_schema
        text, p, c = self.backend.complete(self.messages, 256, 0.1, schema)
        self.assertEqual((json.loads(text)["label"], p, c), ("positive", 42, 7))
        req = self.api.requests[-1]
        body, headers = req["body"], {k.lower(): v for k, v in req["headers"].items()}
        self.assertTrue(req["path"].startswith("/v1/messages"))
        self.assertIn("server-side-fallback-2026-07-01", headers["anthropic-beta"])
        self.assertEqual(body["model"], "claude-opus-5-5")
        self.assertEqual(body["fallbacks"], "default")
        self.assertEqual(body["max_tokens"], 256)
        self.assertEqual(body["system"], "TASK_KIND: classify_sentiment\nBe brief.")
        self.assertEqual(body["messages"], [self.messages[1]])  # only this agent's turn
        self.assertEqual(body["output_config"]["effort"], "low")
        fmt = body["output_config"]["format"]
        self.assertEqual(fmt["type"], "json_schema")
        self.assertEqual(fmt["schema"]["properties"]["label"]["enum"],
                         ["positive", "negative", "neutral"])
        self.assertNotIn("minimum", fmt["schema"]["properties"]["confidence"])
        for banned in ("temperature", "top_p", "top_k", "thinking"):
            self.assertNotIn(banned, body)

    def test_fallbacks_can_be_disabled(self):
        self.cfg.refusal_fallbacks = False
        self.backend.complete(self.messages, 64, 0.1, None)
        body = self.api.requests[-1]["body"]
        self.assertNotIn("fallbacks", body)
        self.assertNotIn("format", body["output_config"])

    def test_refusal_max_tokens_and_errors_raise(self):
        self.api.reply = {"text": "", "stop_reason": "refusal", "status": 200}
        with self.assertRaisesRegex(InferenceError, "declined.*cyber"):
            self.backend.complete(self.messages, 64, 0.1, None)
        self.api.reply = {"text": '{"lab', "stop_reason": "max_tokens", "status": 200}
        with self.assertRaisesRegex(InferenceError, "max_tokens"):
            self.backend.complete(self.messages, 64, 0.1, None)
        self.api.reply = {"text": "", "stop_reason": "end_turn", "status": 400}
        with self.assertRaisesRegex(InferenceError, "rejected"):
            self.backend.complete(self.messages, 64, 0.1, None)

    def test_harness_end_to_end_over_api(self):
        from blockswarm.inference import Completion

        async def infer(msgs, schema):
            text, p, c = await asyncio.to_thread(self.backend.complete, msgs, 256, 0.1, schema)
            return Completion(text, p, c, "anthropic", False, 0.0)

        class Mem:
            async def recent(self, n): return []
            async def put(self, k, v): pass

        from blockswarm.tasks import KINDS as K
        harness = AgentHarness(AgentContext("bsa1x", "00", Mem(), infer, None))
        result = asyncio.run(harness._run_llm(K["classify_sentiment"], {"text": "great"}))
        self.assertEqual(result.output, {"label": "positive", "confidence": 0.9})
        self.assertFalse(result.mock)

    def test_preflight(self):
        self.backend.preflight()  # credentials + model OK
        self.cfg.model = "claude-nonexistent"
        with self.assertRaisesRegex(InferenceError, "unknown model"):
            self.backend.preflight()
        self.cfg.model = "claude-opus-5-5"
        self.api.reply = {"text": "", "stop_reason": "end_turn", "status": 401}
        with self.assertRaisesRegex(ServiceUnavailable, "credentials"):
            self.backend.preflight()

    def test_service_errors_are_classified(self):
        self.api.reply = {"text": "", "stop_reason": "end_turn", "status": 503}
        with self.assertRaisesRegex(ServiceUnavailable, "503"):
            self.backend.complete(self.messages, 64, 0.1, None)
        dead = AnthropicBackend(self.cfg, client=anthropic.Anthropic(
            api_key="k", base_url="http://127.0.0.1:9", max_retries=0))
        with self.assertRaisesRegex(ServiceUnavailable, "reach"):
            dead.complete(self.messages, 64, 0.1, None)

    def test_make_backend_uses_sdk_credentials(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}):
            self.assertIsInstance(make_backend(InferenceConfig()), AnthropicBackend)


if __name__ == "__main__":
    unittest.main()
