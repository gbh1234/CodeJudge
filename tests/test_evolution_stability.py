import sqlite3
import threading
import unittest

from evoagent.evolution import EvolutionEngine, RegressionEvaluator
from evoagent.models import Finding, Severity
from evoagent.store import TaskStore


CLEAN_DIFF = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+value = int(raw)\n"
RISK_DIFF = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"


class MemoryTaskStore(TaskStore):
    def __init__(self):
        self.path = ":memory:"
        self._lock = threading.Lock()
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self._init()

    def _connect(self):
        return self.connection

    def close(self):
        self.connection.close()


def finding(parsed, rule="FAKE", severity=Severity.MEDIUM):
    line = parsed.added_lines[0]
    return Finding(
        rule, severity, "finding", "explanation", line.path, line.line,
        line.content, "fix", "test", 0.8,
    )


class EvolutionStabilityTests(unittest.TestCase):
    def store(self):
        store = MemoryTaskStore()
        self.addCleanup(store.close)
        return store

    def test_two_of_three_predictions_form_consensus(self):
        class Reviewer:
            def __init__(self):
                self.calls = 0

            def review(self, _diff, parsed):
                self.calls += 1
                return [finding(parsed)] if self.calls == 1 else []

        metrics = RegressionEvaluator(
            lambda _prompt: Reviewer(), repeats=3
        ).run("prompt", [{
            "id": 1, "name": "clean-consensus",
            "diff": CLEAN_DIFF, "expected": [],
        }])
        self.assertEqual(1.0, metrics["clean_accuracy"])
        self.assertEqual(2, metrics["case_results"][0]["consensus_votes"])
        self.assertEqual([], metrics["unstable_cases"])

    def test_holdout_redaction_hides_unstable_case_names(self):
        redacted = EvolutionEngine._redact_holdout_metrics({
            "errors": [{"name": "secret-holdout"}],
            "case_results": [{"name": "secret-holdout"}],
            "unstable_cases": ["secret-holdout"],
            "score": 0.0,
        })
        self.assertNotIn("secret-holdout", str(redacted))
        self.assertEqual(1, redacted["unstable_case_count"])

    def test_three_different_predictions_are_inconclusive(self):
        store = self.store()
        store.save_evaluation_case("unstable", "validation", CLEAN_DIFF, [], "test")

        class Reviewer:
            def __init__(self, prompt):
                self.prompt = prompt
                self.calls = 0

            def review(self, _diff, parsed):
                if "candidate" not in self.prompt:
                    return []
                severity = (Severity.LOW, Severity.MEDIUM, Severity.HIGH)[self.calls]
                self.calls += 1
                return [finding(parsed, severity=severity)]

        result = EvolutionEngine(
            store, reviewer_factory=Reviewer, min_cases=1, max_cases=1,
            seed_defaults=False, eval_repeats=3,
        ).propose(
            "llm-review",
            "candidate: Review the diff and return JSON with severity, fix and test.",
        )
        self.assertEqual("inconclusive", result["decision"])
        self.assertFalse(result["gates"]["evaluation_stable"])

    def test_high_risk_minimum_severity_is_a_hard_gate(self):
        store = self.store()
        store.save_evaluation_case(
            "high-risk", "validation", RISK_DIFF,
            [{"path": "a.py", "line": 1, "min_severity": "high"}], "test",
        )

        class Reviewer:
            def __init__(self, prompt):
                self.prompt = prompt

            def review(self, _diff, parsed):
                return (
                    [finding(parsed, "SEC-EVAL", Severity.MEDIUM)]
                    if "candidate" in self.prompt else []
                )

        result = EvolutionEngine(
            store, reviewer_factory=Reviewer, min_cases=1, max_cases=1,
            seed_defaults=False, eval_repeats=3,
        ).propose(
            "llm-review",
            "candidate: Review the diff and return JSON with severity, fix and test.",
        )
        self.assertEqual("rejected", result["decision"])
        self.assertFalse(result["gates"]["validation_high_risk_preserved"])

    def test_feedback_linked_validation_case_must_pass(self):
        store = self.store()
        store.create("task", "org/repo", 1, {"source": "test"})
        store.save_task_payload("task", CLEAN_DIFF)
        store.record_failure_case("task", "false_positive", {"note": "not a defect"})
        store.save_evaluation_case(
            "feedback-target", "validation", CLEAN_DIFF, [], "test"
        )

        class Generator:
            def generate(self, failures, base):
                return {
                    "candidate_prompt": base + "\nCandidate constraint.",
                    "candidate": {}, "clusters": [], "rationale": "",
                    "change_diff": "", "generation": {}, "generator": {},
                    "failure_cases": failures,
                }

        class Reviewer:
            def __init__(self, prompt):
                self.prompt = prompt

            def review(self, _diff, parsed):
                return (
                    [finding(parsed)] if "Candidate constraint" in self.prompt else []
                )

        result = EvolutionEngine(
            store, reviewer_factory=Reviewer, min_cases=1, max_cases=1,
            seed_defaults=False, candidate_generator=Generator(), eval_repeats=3,
        ).auto_propose("llm-review")
        self.assertEqual("rejected", result["decision"])
        self.assertTrue(result["gates"]["feedback_targets_ready"])
        self.assertFalse(result["gates"]["feedback_targets_passed"])


if __name__ == "__main__":
    unittest.main()
