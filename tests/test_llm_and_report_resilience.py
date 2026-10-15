import json
import unittest

from evoagent.agentic_core import AgenticReviewer, BoundedRole
from evoagent.diff_parser import parse_unified_diff
from evoagent.llm import JsonChatClient
from evoagent.report import to_markdown
from evoagent.reviewer import LocalRuleReviewer
from evoagent.runtime import ToolRegistry
from evoagent.telemetry import ExecutionLedger


class JsonAndReportResilienceTests(unittest.TestCase):
    def test_json_parser_accepts_markdown_and_trailing_content(self):
        fenced = '```json\n{"action":"final","findings":[]}\n```'
        repeated = '{"action":"final","findings":[]}\n{"extra":true}'

        self.assertEqual(
            "final", JsonChatClient._parse_json_object(fenced)["action"]
        )
        self.assertEqual(
            "final", JsonChatClient._parse_json_object(repeated)["action"]
        )

    def test_deepseek_json_requests_disable_thinking_mode(self):
        class CapturingClient(JsonChatClient):
            def __init__(self):
                super().__init__("https://example.test", "key", "deepseek-flash", "deepseek")
                self.payload = None

            def _complete_once(self, role, payload, ledger):
                self.payload = payload
                return {"action": "final", "findings": []}

        client = CapturingClient()
        client.complete_json("security", "Return JSON.", "{}", max_tokens=256)

        self.assertEqual({"type": "disabled"}, client.payload["thinking"])
        self.assertEqual({"type": "json_object"}, client.payload["response_format"])

    def test_bounded_role_retries_an_invalid_action_once(self):
        class InvalidThenFinalClient:
            def __init__(self):
                self.calls = 0

            def complete_json(self, role, _system, _user, ledger=None, max_tokens=None):
                self.calls += 1
                if ledger:
                    ledger.record_model(role, "fake", "fake", {}, 1)
                if self.calls == 1:
                    return {"findings": []}
                return {"action": "final", "findings": []}

        client = InvalidThenFinalClient()
        result = BoundedRole(
            "security", "Return JSON.", client, 1000, 10, max_steps=1,
        ).run(
            json.dumps({"phase": "worker"}), ToolRegistry(),
            ExecutionLedger("agentic"),
        )

        self.assertEqual("final", result["action"])
        self.assertEqual(2, client.calls)

    def test_critic_adjustment_is_advisory_and_lead_applies_once(self):
        diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+eval(user_input)\n"
        finding = LocalRuleReviewer().review(diff, parse_unified_diff(diff))[0]

        candidates, decisions = AgenticReviewer._apply_critic({
            "decisions": [{
                "finding_index": 0, "accepted": True,
                "objections": [], "confidence_adjustment": -0.2,
            }],
        }, [finding])
        accepted = AgenticReviewer._apply_lead_final({
            "accepted_finding_indices": [0],
            "confidence_adjustments": [{"finding_index": 0, "adjustment": -0.2}],
        }, candidates)

        self.assertEqual(-0.2, decisions[0]["confidence_adjustment"])
        self.assertAlmostEqual(0.7, accepted[0].confidence)

    def test_lead_has_final_authority_over_severity(self):
        diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+eval(user_input)\n"
        finding = LocalRuleReviewer().review(diff, parse_unified_diff(diff))[0]

        accepted = AgenticReviewer._apply_lead_final({
            "accepted_finding_indices": [0],
            "severity_adjustments": [{"finding_index": 0, "severity": "high"}],
        }, [finding])

        self.assertEqual("high", accepted[0].severity.value)

    def test_markdown_uses_the_persisted_candidate_count_and_degraded_warning(self):
        markdown = to_markdown({
            "repository": "demo/api",
            "pull_request": 12,
            "risk": "unknown",
            "reviewer": "agentic-reviewer",
            "summary": "Review completed in degraded mode.",
            "findings": [],
            "run_mode": {"requested": "agentic", "effective": "agentic"},
            "execution": {"llm_calls": 4, "tool_calls": 1},
            "collaboration": {
                "protocol": "lead-workers",
                "roles": ["lead", "security", "correctness-reliability", "critic"],
                "candidate_findings_before_critic": 1,
                "critic_decisions": [{"finding_index": 0, "accepted": True}],
                "degraded": True,
                "worker_failures": 2,
            },
        })

        self.assertIn("Candidate findings: `1`", markdown)
        self.assertIn("Degraded review", markdown)
        self.assertNotIn("✅ No actionable issue", markdown)


if __name__ == "__main__":
    unittest.main()
