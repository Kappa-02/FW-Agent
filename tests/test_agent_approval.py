import importlib
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from langchain_core.messages import AIMessage, HumanMessage


class LocalModel:
    """Deterministic stand-in for Gemini; exercises the real LangGraph workflow."""
    planned_tool = "draft_firewall_rule"
    planned_ip = "203.0.113.10"

    def bind_tools(self, tools):
        return SimpleNamespace(invoke=lambda messages: self.respond(tools, messages))

    def respond(self, tools, messages):
        if tools[0].name != "draft_firewall_rule" or messages[-1].type == "tool":
            return AIMessage(content="Local test response.")
        args = {"ip_address": self.planned_ip, "firewall_type": "iptables"}
        if self.planned_tool == "deploy_honeypot":
            args = {"target_server": "demo", "attacker_ip": self.planned_ip}
        return AIMessage(content="", tool_calls=[{
            "name": self.planned_tool, "args": args, "id": str(uuid.uuid4())
        }])


class AgentApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("langchain_google_genai.ChatGoogleGenerativeAI", return_value=LocalModel()):
            cls.soc = importlib.import_module("agents.soc_graph")

    def setUp(self):
        LocalModel.planned_tool = "draft_firewall_rule"
        LocalModel.planned_ip = "203.0.113.10"
        self.calls = []
        tool = SimpleNamespace(invoke=lambda args: self.calls.append(args) or "DRAFT NOT APPLIED")
        self.tools_patch = patch.dict(self.soc.mitigation_dict, {
            "draft_firewall_rule": tool, "deploy_honeypot": tool
        })
        self.tools_patch.start()
        self.addCleanup(self.tools_patch.stop)
        self.config = {"configurable": {"thread_id": str(uuid.uuid4())}}
        self.soc.graph.invoke({"messages": [HumanMessage(content="Analyse the demo logs")]}, self.config)
        self.assertIn("human_approval_node", self.soc.graph.get_state(self.config).next)

    def resume(self, actions=(), ips=()):
        self.soc.graph.update_state(self.config, {
            "messages": [HumanMessage(content="Please generate the rule")],
            "approved_actions": list(actions), "approved_ips": list(ips)
        }, as_node="human_approval_node")
        return self.soc.graph.invoke(None, self.config)

    def test_an_imperative_chat_message_is_not_approval(self):
        self.resume()
        self.assertEqual(self.calls, [])

    def test_approval_is_limited_to_selected_ips(self):
        self.resume(["draft_firewall_rule"], ["198.51.100.20"])
        self.assertEqual(self.calls, [])

    def test_approval_is_limited_to_selected_actions(self):
        LocalModel.planned_tool = "deploy_honeypot"
        self.resume(["draft_firewall_rule"], ["203.0.113.10"])
        self.assertEqual(self.calls, [])

    def test_explicit_matching_approval_allows_the_tool(self):
        result = self.resume(["draft_firewall_rule"], ["203.0.113.10"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["ip_address"], "203.0.113.10")
        self.assertEqual(result.get("approved_actions"), [])
        self.assertEqual(result.get("approved_ips"), [])

    def test_approval_is_not_reused_by_a_followup_message(self):
        self.resume(["draft_firewall_rule"], ["203.0.113.10"])
        self.resume()
        self.assertEqual(len(self.calls), 1)

    def test_model_failure_after_a_tool_preserves_its_result_and_consumes_approval(self):
        response = AIMessage(content="", tool_calls=[{
            "name": "draft_firewall_rule",
            "args": {"ip_address": "203.0.113.10", "firewall_type": "iptables"},
            "id": str(uuid.uuid4()),
        }])
        with patch.object(self.soc.mitigation_llm, "invoke", side_effect=[response, RuntimeError("model unavailable")]):
            result = self.resume(["draft_firewall_rule"], ["203.0.113.10"])
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(any(m.type == "tool" and m.content == "DRAFT NOT APPLIED" for m in result["messages"]))
        self.assertIn("MODEL ERROR", result["messages"][-1].content)
        self.assertEqual(result.get("approved_actions"), [])
        self.assertEqual(result.get("approved_ips"), [])
        self.resume()
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
