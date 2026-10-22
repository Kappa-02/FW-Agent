import os
import importlib
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from tests.test_agent_approval import LocalModel

APP = Path(__file__).resolve().parents[1] / "app_soc.py"


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("langchain_google_genai.ChatGoogleGenerativeAI", return_value=LocalModel()):
            importlib.import_module("agents.soc_graph")

    def test_dashboard_opens_without_an_api_key_or_model_calls(self):
        with patch.dict(os.environ, {}, clear=True), patch("dotenv.load_dotenv", return_value=False):
            app = AppTest.from_file(str(APP)).run(timeout=15)
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(app.button(key="analyse_logs").disabled)
        self.assertEqual(app.metric[0].value, "55")
        self.assertTrue(any("dimostrativ" in c.value.lower() for c in app.caption))

    def test_action_buttons_require_confirmation_and_an_ip(self):
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-placeholder"}), patch("dotenv.load_dotenv", return_value=False):
            app = AppTest.from_file(str(APP))
            app.session_state["is_paused_status"] = True
            app.session_state["detected_ips"] = ["203.0.113.10"]
            app.run(timeout=15)
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(app.button(key="fw").disabled)
            self.assertTrue(app.button(key="hp").disabled)
            app.checkbox(key="confirm_actions").check().run(timeout=15)
            self.assertFalse(app.button(key="fw").disabled)
            self.assertFalse(app.button(key="hp").disabled)


if __name__ == "__main__":
    unittest.main()
