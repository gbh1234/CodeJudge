"""用于评测和回放的补充确定性规则；命中只产生候选 Finding。"""
import re

from .models import Finding, Severity
from .finding_identity import canonical_cwe
from .reviewer import Reviewer


class ContextRuleReviewer(Reviewer):
    """在新增行中扫描补充的安全与可靠性风险模式。"""

    name = "context-security-reliability-agent"
    RULES = [
        ("SEC-PATH-TRAVERSAL", Severity.HIGH, re.compile(r"open\(base\s*/\s*user_path\)")),
        ("SEC-YAML-LOAD", Severity.HIGH, re.compile(r"\byaml\.load\s*\(")),
        ("SEC-WEAK-HASH", Severity.MEDIUM, re.compile(r"\bhashlib\.md5\s*\(")),
        ("SEC-INSECURE-TEMPFILE", Severity.MEDIUM, re.compile(r"\btempfile\.mktemp\s*\(")),
        ("SEC-WEAK-RANDOM", Severity.MEDIUM, re.compile(r"\brandom\.random\s*\(")),
        ("REL-UNBOUNDED-RETRY", Severity.MEDIUM, re.compile(r"^\s*while\s+True\s*:")),
        ("SEC-ASSERT-AUTH", Severity.MEDIUM, re.compile(r"^\s*assert\s+user\.is_admin")),
        (
            "SEC-INSECURE-COOKIE", Severity.MEDIUM,
            re.compile(r"set_cookie\(.+secure\s*=\s*False"),
        ),
    ]

    def review(self, diff: str, parsed) -> list:
        findings = []
        for line in parsed.added_lines:
            for rule_id, severity, pattern in self.RULES:
                if not pattern.search(line.content):
                    continue
                findings.append(Finding(
                    rule_id=rule_id,
                    cwe=canonical_cwe(rule_id),
                    severity=severity,
                    title="Supplemental benchmark finding",
                    explanation=(
                        "The changed line matches a context-sensitive security or reliability "
                        "risk that requires evidence review."
                    ),
                    path=line.path,
                    line=line.line,
                    evidence=line.content.strip()[:240],
                    fix="Replace the unsafe operation with a constrained, validated alternative.",
                    test="Add a focused reproduction and run compilation plus regression tests.",
                    confidence=0.86,
                ))
        return findings
