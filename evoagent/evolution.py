"""提示词进化与回放评测。

人工反馈先生成候选提示词，候选再分别通过 Validation、隐藏 Holdout、稳定性共识
和高危能力硬门禁。只有证据表明整体提升且关键能力不退化时，版本才允许激活。
"""

import hashlib
import json
import re
import threading
import uuid
from collections import Counter
from typing import Any, Callable, Dict, List, Optional

from .diff_parser import parse_unified_diff
from .evaluation_harness import one_to_one_match
from .finding_identity import canonical_identity, is_valid_cwe
from .store import utc_now


DEFAULT_PROMPT = (
    "Review the unified diff. Return JSON findings with severity, fix and test. "
    "Report only actionable defects introduced by added lines."
)

DEFAULT_EVALUATION_CASES = [
    {
        "name": "security-dynamic-execution",
        "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+result = eval(user_input)\n",
        "expected": [{"path": "app.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "security-hardcoded-secret",
        "diff": "--- a/config.py\n+++ b/config.py\n@@ -1 +1 @@\n-old\n+api_key = \"production-secret\"\n",
        "expected": [{"path": "config.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "reliability-swallowed-error",
        "diff": "--- a/jobs.py\n+++ b/jobs.py\n@@ -1 +1 @@\n-old\n+except Exception: pass\n",
        "expected": [{"path": "jobs.py", "line": 1, "min_severity": "medium"}],
    },
    {
        "name": "clean-parameterized-query",
        "diff": "--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-old\n+cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n",
        "expected": [],
    },
    {
        "name": "clean-input-validation",
        "diff": "--- a/api.py\n+++ b/api.py\n@@ -1 +1 @@\n-old\n+limit = min(max(int(raw_limit), 1), 100)\n",
        "expected": [],
    },
    {
        "name": "holdout-security-shell-execution",
        "split": "holdout",
        "diff": "--- a/runner.py\n+++ b/runner.py\n@@ -1 +1 @@\n-old\n+subprocess.run(command, shell=True)\n",
        "expected": [{"path": "runner.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "holdout-clean-environment-secret",
        "split": "holdout",
        "diff": "--- a/config.py\n+++ b/config.py\n@@ -1 +1 @@\n-old\n+api_key = os.environ[\"API_KEY\"]\n",
        "expected": [],
    },
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class RegressionEvaluator:
    """用固定数据集重复回放一个提示词，并计算可比较的客观审查指标。"""

    def __init__(
        self, reviewer_factory: Callable[[str], object], line_tolerance: int = 2,
        repeats: int = 3,
    ):
        self.reviewer_factory = reviewer_factory
        self.line_tolerance = max(0, int(line_tolerance))
        self.repeats = max(1, int(repeats))
        self.consensus_threshold = self.repeats // 2 + 1

    @staticmethod
    def _prediction_signature(findings: List[object]) -> tuple:
        return tuple(sorted(
            (
                str(finding.path), int(finding.line),
                canonical_identity(finding.rule_id, finding.cwe),
                finding.severity.value,
            )
            for finding in findings
        ))

    def _evaluate_attempt(
        self, reviewer: object, case: dict, parsed: object, expected_items: List[dict],
    ) -> Dict[str, Any]:
        """执行单次案例回放，并以一对一匹配计算命中、误报和严重度结果。"""
        findings = reviewer.review(case["diff"], parsed)
        predicted = {}
        predicted_findings_by_key = {}
        for finding in findings:
            key = (
                finding.path, int(finding.line),
                canonical_identity(finding.rule_id, finding.cwe),
            )
            current = predicted.get(key)
            severity = finding.severity.value
            if current is None or SEVERITY_RANK[severity] > SEVERITY_RANK[current]:
                predicted[key] = severity
                predicted_findings_by_key[key] = finding

        match_expected = [
            {
                "path": item["path"],
                "start_line": int(item.get("line", item.get("start_line"))),
                "end_line": int(item.get("end_line", item.get("line", item.get("start_line")))),
                "cwe": canonical_identity(
                    item.get("rule_id", ""), item.get("cwe", "")
                ) if item.get("rule_id") or item.get("cwe") else "",
            }
            for item in expected_items
        ]
        predicted_findings = [predicted_findings_by_key[key] for key in predicted]
        matches = one_to_one_match(
            match_expected, predicted_findings,
            line_tolerance=self.line_tolerance,
        )
        matched_predicted = {item.predicted_index for item in matches}
        severity_ok = high_hits = 0
        for match in matches:
            expected = expected_items[match.expected_index]
            finding = predicted_findings[match.predicted_index]
            minimum = str(
                expected.get("min_severity", expected.get("severity", "low"))
            ).lower()
            severity_passed = (
                SEVERITY_RANK[finding.severity.value] >= SEVERITY_RANK[minimum]
            )
            severity_ok += int(severity_passed)
            if SEVERITY_RANK[minimum] >= SEVERITY_RANK["high"]:
                high_hits += int(severity_passed)

        high_expected = sum(
            SEVERITY_RANK[str(
                item.get("min_severity", item.get("severity", "low"))
            ).lower()]
            >= SEVERITY_RANK["high"]
            for item in expected_items
        )
        return {
            "signature": self._prediction_signature(predicted_findings),
            "tp": len(matches),
            "fp": len(predicted_findings) - len(matched_predicted),
            "fn": len(expected_items) - len(matches),
            "findings": len(predicted_findings),
            "severity_hits": severity_ok,
            "high_severity_hits": high_hits,
            "high_severity_expected": high_expected,
        }

    def run(self, prompt: str, cases: List[dict]) -> Dict[str, Any]:
        """每个案例重复运行，以多数一致结果抵抗模型的随机波动。"""
        reviewer = self.reviewer_factory(prompt)
        reviewer_name = str(getattr(reviewer, "name", reviewer.__class__.__name__))
        true_positive = false_positive = false_negative = 0
        severity_hits = matched = clean_hits = clean_total = 0
        high_severity_hits = high_severity_total = 0
        expected_total = predicted_total = 0
        errors = []
        case_results = []

        agreement_votes = attempt_errors = 0
        unstable_cases = []
        for case in cases:
            expected_items = list(case.get("expected", []))
            expected_total += len(expected_items)
            clean_total += int(not expected_items)
            parsed = parse_unified_diff(case["diff"])
            attempts = []
            case_attempt_errors = []
            for _ in range(self.repeats):
                try:
                    attempts.append(self._evaluate_attempt(
                        reviewer, case, parsed, expected_items
                    ))
                except Exception as exc:
                    attempt_errors += 1
                    case_attempt_errors.append(str(exc)[:500])

            signatures = Counter(item["signature"] for item in attempts)
            signature, votes = signatures.most_common(1)[0] if signatures else ((), 0)
            agreement_votes += votes
            if votes < self.consensus_threshold:
                unstable_cases.append(case["name"])
                false_negative += len(expected_items)
                case_high_total = sum(
                    SEVERITY_RANK.get(str(
                        item.get("min_severity", item.get("severity", "low"))
                    ).lower(), 0)
                    >= SEVERITY_RANK["high"]
                    for item in expected_items
                )
                high_severity_total += case_high_total
                error = (
                    "replay did not reach consensus"
                    if attempts else
                    "all replay attempts failed: %s" % (
                        case_attempt_errors[0] if case_attempt_errors else "unknown error"
                    )
                )
                errors.append({"name": case["name"], "error": error})
                case_results.append({
                    "id": case.get("id"), "name": case["name"], "tp": 0, "fp": 0,
                    "fn": len(expected_items), "findings": 0, "severity_hits": 0,
                    "high_severity_hits": 0,
                    "high_severity_expected": case_high_total,
                    "attempts": self.repeats, "consensus_votes": votes,
                    "agreement_rate": round(votes / self.repeats, 4),
                    "stable": False, "error": error,
                })
                continue

            selected = next(item for item in attempts if item["signature"] == signature)
            tp, fp, fn = selected["tp"], selected["fp"], selected["fn"]
            true_positive += tp
            false_positive += fp
            false_negative += fn
            matched += tp
            severity_hits += selected["severity_hits"]
            high_severity_total += selected["high_severity_expected"]
            high_severity_hits += selected["high_severity_hits"]
            predicted_total += selected["findings"]
            if not expected_items:
                clean_hits += int(selected["findings"] == 0)
            case_results.append({
                "id": case.get("id"), "name": case["name"],
                "tp": tp, "fp": fp, "fn": fn,
                "findings": selected["findings"],
                "severity_hits": selected["severity_hits"],
                "high_severity_hits": selected["high_severity_hits"],
                "high_severity_expected": selected["high_severity_expected"],
                "attempts": self.repeats, "consensus_votes": votes,
                "agreement_rate": round(votes / self.repeats, 4),
                "stable": True, "error": None,
            })

        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive else (1.0 if true_positive + false_negative == 0 else 0.0)
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative else 1.0
        )
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        severity_accuracy = severity_hits / matched if matched else (1.0 if not false_negative else 0.0)
        clean_accuracy = clean_hits / clean_total if clean_total else 1.0
        high_severity_recall = (
            high_severity_hits / high_severity_total if high_severity_total else 1.0
        )
        successful_cases = len(cases) - len(errors)
        success_rate = successful_cases / len(cases) if cases else 0.0
        components = []
        if expected_total:
            components.extend(((f1, 0.65), (severity_accuracy, 0.15)))
        if clean_total:
            components.append((clean_accuracy, 0.20))
        score = (
            sum(value * weight for value, weight in components)
            / sum(weight for _, weight in components)
            if components else 0.0
        )
        score *= success_rate
        return {
            "schema_version": 3,
            "reviewer": reviewer_name,
            "score": round(score, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "severity_accuracy": round(severity_accuracy, 4),
            "high_severity_recall": round(high_severity_recall, 4),
            "clean_accuracy": round(clean_accuracy, 4),
            "cases": len(cases),
            "positive_cases": sum(bool(case.get("expected")) for case in cases),
            "clean_cases": clean_total,
            "expected_findings": expected_total,
            "predicted_findings": predicted_total,
            "successful_cases": successful_cases,
            "success_rate": round(success_rate, 4),
            "evaluation_repeats": self.repeats,
            "consensus_threshold": self.consensus_threshold,
            "agreement_rate": round(
                agreement_votes / (len(cases) * self.repeats), 4
            ) if cases else 1.0,
            "unstable_cases": unstable_cases,
            "attempt_errors": attempt_errors,
            "errors": errors,
            "case_results": case_results,
        }


class EvolutionEngine:
    """以回放评测、审计记录和激活门禁约束提示词的版本演进。"""

    FORBIDDEN = ("ignore previous", "disable safety", "bypass", "直接执行生产")
    FEEDBACK_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_-]{1,79}$")

    def __init__(
        self, store, reviewer_factory: Optional[Callable[[str], object]] = None,
        min_cases: int = 3, max_cases: int = 5, min_improvement: float = 0.01,
        min_holdout_cases: int = 0, max_metric_regression: float = 0.0,
        seed_defaults: bool = True, candidate_generator=None, eval_repeats: int = 3,
    ):
        self.store = store
        self.reviewer_factory = reviewer_factory
        self.min_cases = min_cases
        self.max_cases = max_cases
        self.min_improvement = min_improvement
        self.min_holdout_cases = min_holdout_cases
        self.max_metric_regression = max_metric_regression
        self.candidate_generator = candidate_generator
        self.eval_repeats = max(1, int(eval_repeats))
        self._lock = threading.RLock()
        if seed_defaults:
            self._seed_default_cases()

    def _seed_default_cases(self) -> None:
        """幂等写入内置的基础安全、可靠性与干净案例。"""
        for case in DEFAULT_EVALUATION_CASES:
            self.store.save_evaluation_case(
                case["name"], case.get("split", "validation"), case["diff"],
                case["expected"], "builtin", True
            )

    @staticmethod
    def validate_case(name: str, diff: str, expected: list, split: str = "validation") -> None:
        """在入库前校验案例格式、变更位置及预期 Finding 的合法性。"""
        if not name or len(name) > 120:
            raise ValueError("evaluation case name is required and must be at most 120 characters")
        if split not in {"train", "validation", "holdout"}:
            raise ValueError("evaluation split must be train, validation or holdout")
        if len(diff.encode("utf-8")) > 1024 * 1024:
            raise ValueError("evaluation case diff must be at most 1 MiB")
        parsed = parse_unified_diff(diff)
        if not parsed.added_lines:
            raise ValueError("evaluation case must contain a valid unified diff with added lines")
        valid_locations = {(line.path, line.line) for line in parsed.added_lines}
        if not isinstance(expected, list):
            raise ValueError("expected_findings must be an array")
        if len(expected) > 100:
            raise ValueError("expected_findings must contain at most 100 items")
        seen = set()
        for item in expected:
            if not isinstance(item, dict):
                raise ValueError("each expected finding must be an object")
            try:
                path = str(item.get("path", ""))
                start_line = int(item.get("line", item.get("start_line", 0)))
                end_line = int(item.get("end_line", start_line))
            except (TypeError, ValueError) as exc:
                raise ValueError("expected finding line must be an integer") from exc
            if start_line > end_line:
                raise ValueError("expected finding line range is inverted")
            if not any(
                changed_path == path and start_line <= changed_line <= end_line
                for changed_path, changed_line in valid_locations
            ):
                raise ValueError("expected finding must point to an added line: %s:%s" % (path, start_line))
            minimum = item.get("min_severity", item.get("severity", "low"))
            if str(minimum).lower() not in SEVERITY_RANK:
                raise ValueError("invalid min_severity")
            rule_id = str(item.get("rule_id", "")).strip()
            if "rule_id" in item and (not rule_id or len(rule_id) > 80):
                raise ValueError("rule_id must be non-empty and at most 80 characters")
            if "cwe" in item and not is_valid_cwe(item.get("cwe")):
                raise ValueError("cwe must use the CWE-<number> format")
            identity = (path, start_line, end_line, rule_id)
            if identity in seen:
                raise ValueError("duplicate expected finding: %s:%s:%s" % identity)
            seen.add(identity)

    def add_evaluation_case(
        self, name: str, diff: str, expected: list, split: str = "validation",
        source: str = "manual",
    ) -> dict:
        name = name.strip()
        split = split.strip().lower()
        self.validate_case(name, diff, expected, split)
        return self.store.save_evaluation_case(name, split, diff, expected, source[:120], True)

    def safety_evaluate(self, prompt: str) -> Dict[str, Any]:
        normalized = prompt.strip()
        lowered = normalized.lower()
        safety = bool(normalized) and len(normalized) <= 12000 and not any(
            token in lowered for token in self.FORBIDDEN
        )
        required = ("diff", "severity", "fix", "test", "json")
        completeness = sum(token in lowered for token in required) / len(required)
        return {
            "safety_passed": safety,
            "completeness": round(completeness, 4),
            "missing_terms": [token for token in required if token not in lowered],
        }

    def status(self) -> Dict[str, Any]:
        cases = self.store.list_evaluation_cases("validation", True, self.max_cases)
        holdout = self.store.list_evaluation_cases("holdout", True, self.max_cases)
        return {
            "model_configured": self.reviewer_factory is not None,
            "validation_cases": len(cases),
            "holdout_cases": len(holdout),
            "minimum_cases": self.min_cases,
            "minimum_holdout_cases": self.min_holdout_cases,
            "maximum_cases_per_run": self.max_cases,
            "minimum_improvement": self.min_improvement,
            "maximum_metric_regression": self.max_metric_regression,
            "evaluation_repeats": self.eval_repeats,
            "consensus_threshold": self.eval_repeats // 2 + 1,
            "validation_dataset_fingerprint": self._dataset_fingerprint(cases),
            "holdout_dataset_fingerprint": self._dataset_fingerprint(holdout),
            "ready": (
                self.reviewer_factory is not None
                and len(cases) >= self.min_cases
                and len(holdout) >= self.min_holdout_cases
            ),
        }

    def propose(
        self, skill_name: str, prompt: str, regression_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        skill_name = skill_name.strip()
        if not skill_name or len(skill_name) > 120:
            raise ValueError("skill_name is required and must be at most 120 characters")
        with self._lock:
            return self._propose(skill_name, prompt, regression_score)

    def _propose(
        self, skill_name: str, prompt: str, regression_score: Optional[float],
        activation_policy: str = "auto",
        feedback_target_hashes: Optional[set] = None,
    ) -> Dict[str, Any]:
        """执行候选评测和全部门禁，并持久化版本、结论与可复现元数据。"""
        safety = self.safety_evaluate(prompt)
        active = self.store.get_active_skill_version(skill_name)
        if active and prompt.strip() == active["prompt"].strip():
            return {
                "version": {
                    "skill_name": active["skill_name"],
                    "version": active["version"],
                    "score": active["score"],
                    "active": bool(active["active"]),
                },
                "decision": "deferred",
                "reason": "candidate prompt is identical to the active version",
                "candidate": self._empty_metrics(0),
                "baseline": self._empty_metrics(0),
                "candidate_holdout": self._redact_holdout_metrics(self._empty_metrics(0)),
                "baseline_holdout": self._redact_holdout_metrics(self._empty_metrics(0)),
                "safety": safety,
                "run_id": None,
            }
        baseline_prompt = active["prompt"] if active else DEFAULT_PROMPT
        cases = self.store.list_evaluation_cases("validation", True, self.max_cases)
        holdout_cases = self.store.list_evaluation_cases("holdout", True, self.max_cases)
        target_hashes = set(feedback_target_hashes or set())
        target_case_names = sorted({
            str(case["name"]) for case in cases
            if self._sha256(str(case.get("diff", ""))) in target_hashes
        })
        targets_required = bool(target_hashes)

        decision = "deferred"
        reason = ""
        candidate_metrics = self._empty_metrics(len(cases))
        baseline_metrics = self._empty_metrics(len(cases))
        candidate_holdout = self._empty_metrics(len(holdout_cases))
        baseline_holdout = self._empty_metrics(len(holdout_cases))
        gates = {
            "safety": safety["safety_passed"] and safety["completeness"] == 1.0,
            "validation_dataset_ready": len(cases) >= self.min_cases,
            "holdout_dataset_ready": len(holdout_cases) >= self.min_holdout_cases,
            "evaluation_success": None,
            "evaluation_stable": None,
            "validation_improvement": None,
            "validation_non_regression": None,
            "holdout_non_regression": None,
            "validation_high_risk_preserved": None,
            "holdout_high_risk_preserved": None,
            "feedback_targets_ready": (
                bool(target_case_names) if targets_required else None
            ),
            "feedback_targets_passed": None,
        }
        if not safety["safety_passed"] or safety["completeness"] < 1.0:
            decision = "rejected"
            reason = "candidate prompt failed the deterministic safety/completeness gate"
        elif self.reviewer_factory is None:
            reason = "candidate saved but no LLM provider is configured; replay evaluation was not run"
        elif len(cases) < self.min_cases:
            reason = "candidate saved but the validation dataset is smaller than the activation minimum"
        elif len(holdout_cases) < self.min_holdout_cases:
            reason = "candidate saved but the holdout dataset is smaller than the activation minimum"
        else:
            evaluator = RegressionEvaluator(
                self.reviewer_factory, repeats=self.eval_repeats
            )
            baseline_metrics = evaluator.run(baseline_prompt, cases)
            candidate_metrics = evaluator.run(prompt, cases)
            if holdout_cases:
                baseline_holdout = evaluator.run(baseline_prompt, holdout_cases)
                candidate_holdout = evaluator.run(prompt, holdout_cases)
            no_errors = not (
                baseline_metrics["errors"] or candidate_metrics["errors"]
                or baseline_holdout["errors"] or candidate_holdout["errors"]
            )
            stable = not (
                baseline_metrics.get("unstable_cases")
                or candidate_metrics.get("unstable_cases")
                or baseline_holdout.get("unstable_cases")
                or candidate_holdout.get("unstable_cases")
            )
            improved = candidate_metrics["score"] >= baseline_metrics["score"] + self.min_improvement
            validation_safe = self._non_regressing(candidate_metrics, baseline_metrics)
            holdout_safe = self._non_regressing(candidate_holdout, baseline_holdout)
            validation_high_risk = self._high_risk_cases_pass(candidate_metrics)
            holdout_high_risk = self._high_risk_cases_pass(candidate_holdout)
            feedback_targets_passed = (
                self._target_cases_pass(candidate_metrics, target_case_names)
                if target_case_names else (not targets_required)
            )
            gates.update({
                "evaluation_success": no_errors,
                "evaluation_stable": stable,
                "validation_improvement": improved,
                "validation_non_regression": validation_safe,
                "holdout_non_regression": holdout_safe,
                "validation_high_risk_preserved": validation_high_risk,
                "holdout_high_risk_preserved": holdout_high_risk,
                "feedback_targets_passed": feedback_targets_passed,
            })
            if not no_errors or not stable:
                decision = "inconclusive"
                reason = "replay evaluation was unstable or failed to reach consensus"
            elif targets_required and not target_case_names:
                decision = "inconclusive"
                reason = "feedback target is not represented in the validation dataset"
            elif (
                improved and validation_safe and holdout_safe
                and validation_high_risk and holdout_high_risk
                and feedback_targets_passed
            ):
                decision = "activated" if activation_policy == "auto" else "shadow_ready"
                reason = (
                    "candidate improved on validation and passed the non-regression holdout gate"
                    if decision == "activated" else
                    "candidate passed replay gates and is awaiting shadow/canary approval"
                )
            else:
                decision = "rejected"
                reasons = []
                if not no_errors:
                    reasons.append("one or more baseline or candidate evaluations failed")
                if not improved:
                    reasons.append("score improvement was below the configured threshold")
                if not validation_safe:
                    reasons.append("a protected validation metric regressed")
                if not holdout_safe:
                    reasons.append("a protected holdout metric regressed")
                if not validation_high_risk:
                    reasons.append("a validation high-risk case missed its minimum severity")
                if not holdout_high_risk:
                    reasons.append("a holdout high-risk case missed its minimum severity")
                if targets_required and not feedback_targets_passed:
                    reasons.append("the candidate did not pass every feedback target case")
                reason = "; ".join(reasons)

        version = self.store.save_skill_version(
            skill_name, prompt.strip(), candidate_metrics["score"], decision == "activated"
        )
        run = {
            "id": str(uuid.uuid4()),
            "skill_name": skill_name,
            "candidate_version": version["version"],
            "baseline_version": active["version"] if active else None,
            "decision": decision,
            "candidate_score": candidate_metrics["score"],
            "baseline_score": baseline_metrics["score"],
            "metrics": {
                "candidate": candidate_metrics,
                "baseline": baseline_metrics,
                "candidate_holdout": self._redact_holdout_metrics(candidate_holdout),
                "baseline_holdout": self._redact_holdout_metrics(baseline_holdout),
                "safety": safety,
                "gates": gates,
                "reason": reason,
                "reproducibility": {
                    "evaluation_schema_version": 3,
                    "evaluation_repeats": self.eval_repeats,
                    "consensus_threshold": self.eval_repeats // 2 + 1,
                    "candidate_prompt_sha256": self._sha256(prompt.strip()),
                    "baseline_prompt_sha256": self._sha256(baseline_prompt),
                    "validation_dataset_sha256": self._dataset_fingerprint(cases),
                    "holdout_dataset_sha256": self._dataset_fingerprint(holdout_cases),
                    "validation_case_ids": [case.get("id") for case in cases],
                    "holdout_case_count": len(holdout_cases),
                    "feedback_target_case_ids": [
                        case.get("id") for case in cases
                        if case.get("name") in target_case_names
                    ],
                },
                "external_regression_score_ignored": regression_score is not None,
            },
            "created_at": utc_now(),
        }
        self.store.save_evolution_run(run)
        return {
            "version": version,
            "decision": decision,
            "reason": reason,
            "candidate": candidate_metrics,
            "baseline": baseline_metrics,
            "candidate_holdout": self._redact_holdout_metrics(candidate_holdout),
            "baseline_holdout": self._redact_holdout_metrics(baseline_holdout),
            "safety": safety,
            "gates": gates,
            "run_id": run["id"],
        }

    def rollback(self, skill_name: str, version: int) -> bool:
        with self._lock:
            return self.store.activate_skill_version(skill_name, version)

    def auto_propose(
        self, skill_name: str = "llm-review", tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """从未解决反馈归纳候选约束，但不允许反馈文本直接成为可执行指令。"""
        cases = self.store.list_failure_cases(True, 100, tenant_id)
        active = self.store.get_active_skill_version(skill_name)
        base = active["prompt"] if active else DEFAULT_PROMPT
        if self.candidate_generator is not None and cases:
            generated = self.candidate_generator.generate(cases, base)
            candidate = generated["candidate_prompt"]
            if candidate.strip() == base.strip():
                return {
                    "version": None, "decision": "deferred",
                    "reason": "root-cause analysis produced no prompt change",
                    "candidate_change": generated,
                    "failure_cases_used": len(cases), "run_id": None,
                }
            feedback_target_hashes = {
                self._sha256(diff)
                for diff in (
                    self.store.get_task_payload(str(item.get("task_id", "")))
                    for item in cases
                    if item.get("category") in {"false_positive", "missed_issue", "bad_fix"}
                )
                if diff
            }
            result = self._propose(
                skill_name, candidate, None, activation_policy="shadow",
                feedback_target_hashes=feedback_target_hashes,
            )
            result["candidate_change"] = generated
            result["failure_cases_used"] = len(cases)
            result["rollback_point"] = (
                {"skill_name": skill_name, "version": active["version"]}
                if active else None
            )
            result["evaluation_data"] = {
                "validation_sha256": self.status()["validation_dataset_fingerprint"],
                "holdout_sha256": self.status()["holdout_dataset_fingerprint"],
            }
            if result.get("run_id"):
                runs = self.store.list_evolution_runs(200)
                run = next((item for item in runs if item["id"] == result["run_id"]), None)
                if run:
                    metrics = dict(run["metrics"])
                    metrics["structured_candidate"] = {
                        "generator": generated["generator"],
                        "failure_cases": generated["failure_cases"],
                        "clusters": generated["clusters"],
                        "change_diff": generated["change_diff"],
                        "candidate": generated["candidate"],
                        "generation_execution": generated["generation"],
                        "evaluation_data": result["evaluation_data"],
                        "rollback_point": result["rollback_point"],
                        "source_code_changes_allowed": False,
                    }
                    self.store.update_evolution_run(
                        result["run_id"], result["decision"], metrics
                    )
            return result
        counts = {}
        for case in cases:
            counts[case["category"]] = counts.get(case["category"], 0) + 1
        directives = []
        if counts.get("false_positive"):
            directives.append("Avoid style-only findings and require direct evidence from an added line.")
        if counts.get("missed_issue"):
            directives.append("Check boundary conditions, authorization, input validation and error paths explicitly.")
        if counts.get("bad_fix"):
            directives.append("Propose minimal fixes that preserve behavior and always include a regression test.")
        if counts.get("execution_error"):
            directives.append("Keep output valid JSON and follow the requested schema exactly.")
        # A missed-issue feedback item may carry the reviewer rule identifier that a
        # human confirmed.  Preserve that signal in the prompt without accepting
        # arbitrary feedback text as an instruction.  The bracketed marker is both
        # human-readable to an LLM and machine-auditable in offline replay.
        learned_rule_ids = sorted({
            str((case.get("payload", {}).get("finding") or {}).get("rule_id", "")).strip()
            for case in cases
            if case.get("category") == "missed_issue"
        })
        learned_rule_ids = [
            rule_id for rule_id in learned_rule_ids
            if self.FEEDBACK_RULE_ID.fullmatch(rule_id)
        ]
        directives.extend(
            "Explicitly check added lines for confirmed rule %s [focus-rule:%s]."
            % (rule_id, rule_id)
            for rule_id in learned_rule_ids
        )
        additions = [directive for directive in directives if directive.lower() not in base.lower()]
        if not additions:
            return {
                "version": None,
                "decision": "deferred",
                "reason": "no new supported learning signal was found in unresolved feedback",
                "candidate": self._empty_metrics(0),
                "baseline": self._empty_metrics(0),
                "candidate_holdout": self._empty_metrics(0),
                "baseline_holdout": self._empty_metrics(0),
                "safety": self.safety_evaluate(base),
                "run_id": None,
                "failure_cases_used": len(cases),
                "learned_categories": counts,
            }
        candidate = base.rstrip() + (
            "\n\nLearned constraints:\n- " + "\n- ".join(additions)
        )
        result = self.propose(skill_name, candidate)
        result["failure_cases_used"] = len(cases)
        result["learned_categories"] = counts
        result["learned_rule_ids"] = learned_rule_ids
        if result["decision"] == "activated":
            self.store.resolve_failure_cases([case["id"] for case in cases])
        return result

    @staticmethod
    def _empty_metrics(case_count: int) -> Dict[str, Any]:
        return {
            "schema_version": 3,
            "reviewer": "",
            "score": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "severity_accuracy": 0.0, "high_severity_recall": 0.0, "clean_accuracy": 0.0,
            "cases": case_count, "positive_cases": 0, "clean_cases": 0,
            "expected_findings": 0, "predicted_findings": 0,
            "successful_cases": 0, "success_rate": 0.0, "errors": [], "case_results": [],
            "evaluation_repeats": 0, "consensus_threshold": 0,
            "agreement_rate": 0.0, "unstable_cases": [], "attempt_errors": 0,
        }

    @staticmethod
    def _high_risk_cases_pass(metrics: Dict[str, Any]) -> bool:
        """高危案例是硬门禁：必须稳定检出且满足最低严重度。"""
        return all(
            bool(case.get("stable", True))
            and int(case.get("high_severity_hits", 0))
            >= int(case.get("high_severity_expected", 0))
            for case in metrics.get("case_results", [])
            if int(case.get("high_severity_expected", 0)) > 0
        )

    @staticmethod
    def _target_cases_pass(metrics: Dict[str, Any], target_names: List[str]) -> bool:
        """本轮反馈所针对的案例必须全部稳定、无漏报、无误报。"""
        by_name = {
            str(case.get("name")): case for case in metrics.get("case_results", [])
        }
        for name in target_names:
            case = by_name.get(name)
            if not case or not case.get("stable", False):
                return False
            expected = int(case.get("tp", 0)) + int(case.get("fn", 0))
            if (
                int(case.get("fn", 0)) > 0
                or int(case.get("fp", 0)) > 0
                or int(case.get("severity_hits", 0)) < expected
            ):
                return False
        return True

    def _non_regressing(self, candidate: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """逐项保护核心指标，禁止用某项提升掩盖另一项退化。"""
        protected = ["score", "precision", "recall", "high_severity_recall"]
        if baseline.get("positive_cases", 0):
            protected.append("severity_accuracy")
        if baseline.get("clean_cases", 0):
            protected.append("clean_accuracy")
        return all(
            float(candidate.get(metric, 0.0)) + self.max_metric_regression
            >= float(baseline.get(metric, 0.0))
            for metric in protected
        )

    @staticmethod
    def _redact_holdout_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
        """只公开 Holdout 汇总指标，隐藏案例细节以降低针对性过拟合风险。"""
        redacted = {
            key: value for key, value in metrics.items()
            if key not in {"errors", "case_results", "unstable_cases"}
        }
        redacted["error_count"] = len(metrics.get("errors", []))
        redacted["unstable_case_count"] = len(metrics.get("unstable_cases", []))
        return redacted

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _dataset_fingerprint(cls, cases: List[dict]) -> str:
        canonical = [
            {
                "name": case.get("name"),
                "split": case.get("split"),
                "diff": case.get("diff"),
                "expected": case.get("expected", []),
            }
            for case in cases
        ]
        payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return cls._sha256(payload)
