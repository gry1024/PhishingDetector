import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.server import app
from src.config import settings


class _LLMStub:
    def chat(self, system_prompt, user_prompt, temperature=None, response_format="text"):
        return "OK"


class HealthLLMTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch("src.api.routes.get_llm", return_value=_LLMStub())
    def test_health_llm_should_report_ok_when_probe_passes(self, _mock_get_llm):
        original_key = settings.llm.api_key
        try:
            settings.llm.api_key = "sk-cp-test-key-123456"
            resp = self.client.get("/api/health/llm?probe=true")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ok")
            self.assertTrue(data["llm"]["api_key_present"])
            self.assertTrue(data["llm"]["probe"]["attempted"])
            self.assertTrue(data["llm"]["probe"]["success"])
            self.assertTrue(data["service"]["signature"]["has_studio_page"])
            self.assertTrue(data["service"]["signature"]["has_v2_stream"])
        finally:
            settings.llm.api_key = original_key

    def test_health_llm_should_fail_when_key_missing(self):
        original_key = settings.llm.api_key
        try:
            settings.llm.api_key = ""
            resp = self.client.get("/api/health/llm?probe=true")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "fail")
            self.assertFalse(data["llm"]["api_key_present"])
            self.assertFalse(data["llm"]["probe"]["attempted"])
        finally:
            settings.llm.api_key = original_key


if __name__ == "__main__":
    unittest.main()
