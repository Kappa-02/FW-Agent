import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import security_tools as tools


class SecurityToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.intel = Path(self.temp.name) / "threat_intel.json"
        self.intel.write_text(json.dumps({"known_malicious_ips": []}))
        self.before = self.intel.read_bytes()
        self.path_patch = patch.object(tools, "THREAT_INTEL_PATH", str(self.intel))
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

    def draft(self, ip="203.0.113.10", firewall="iptables"):
        return tools.draft_firewall_rule.invoke({"ip_address": ip, "firewall_type": firewall})

    def deploy(self, target="demo", attacker="203.0.113.10"):
        return tools.deploy_honeypot.invoke({"target_server": target, "attacker_ip": attacker})

    def test_drafting_does_not_mark_an_ip_as_blocked(self):
        result = self.draft()
        self.assertIn("iptables -A INPUT -s 203.0.113.10 -j DROP", result)
        self.assertEqual(self.intel.read_bytes(), self.before)
        self.assertIn("NOT APPLIED", result)

    def test_invalid_or_non_ipv4_addresses_cannot_become_commands(self):
        for ip in ["invalid", "1.2.3.4; whoami", "1.2.3.4\n--help", "999.1.1.1", "::1"]:
            with self.subTest(ip=ip):
                self.assertTrue(self.draft(ip).startswith("ERROR:"))

    def test_unknown_firewall_is_an_error(self):
        self.assertTrue(self.draft(firewall="perimeter").startswith("ERROR:"))

    def test_docker_is_simulated_by_default_without_writing_intelligence(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(tools.subprocess, "run") as run:
            result = self.deploy()
        run.assert_not_called()
        self.assertIn("SIMULATION", result)
        self.assertIn("no container", result.lower())
        self.assertEqual(self.intel.read_bytes(), self.before)

    def test_invalid_container_target_is_rejected_before_execution(self):
        with patch.dict(os.environ, {"FW_AGENT_ENABLE_DOCKER": "true"}), patch.object(tools.subprocess, "run") as run:
            result = self.deploy(target="../other-container")
        run.assert_not_called()
        self.assertTrue(result.startswith("ERROR:"))

    def test_docker_failure_is_not_reported_as_success_or_simulation(self):
        with patch.dict(os.environ, {"FW_AGENT_ENABLE_DOCKER": "true"}), patch.object(
            tools.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "docker")
        ):
            result = self.deploy()
        self.assertTrue(result.startswith("ERROR:"))
        self.assertNotIn("SUCCESS", result)
        self.assertEqual(self.intel.read_bytes(), self.before)

    def test_opted_in_docker_binds_only_to_loopback_and_never_removes_containers(self):
        with patch.dict(os.environ, {"FW_AGENT_ENABLE_DOCKER": "true"}), patch.object(
            tools.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "container-id\n", "")
        ) as run:
            result = self.deploy()
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["docker", "run", "-d"])
        self.assertIn("127.0.0.1:8080:80", command)
        self.assertNotIn("rm", command)
        self.assertIn("does not block", result.lower())

    def test_documentation_ip_geolocation_is_labelled_synthetic(self):
        with patch.object(tools.requests, "get") as get:
            result = tools.ip_geolocation.invoke({"ip_address": "203.0.113.10"})
        get.assert_not_called()
        self.assertIn("DEMO", result)
        self.assertIn("[COORD:", result)

    def test_private_ip_geolocation_does_not_query_an_external_service(self):
        with patch.object(tools.requests, "get") as get:
            result = tools.ip_geolocation.invoke({"ip_address": "10.0.0.100"})
        get.assert_not_called()
        self.assertIn("unavailable", result.lower())


if __name__ == "__main__":
    unittest.main()
