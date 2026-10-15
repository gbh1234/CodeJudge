"""Submit an intentionally safe PR diff to EvoAgent."""
import getpass
import json
import urllib.error
import urllib.request


BASE_URL = "http://127.0.0.1:8080"


def post_json(path, payload, token=None):
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        BASE_URL + path,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


password = getpass.getpass("管理员密码：")
session = post_json(
    "/v1/auth/login",
    {"username": "admin", "password": password},
)
print("登录成功，租户：", session["tenant_id"])

# 安全案例：有明确类型、边界限制，并同时增加回归测试。
diff = """diff --git a/src/limits.py b/src/limits.py
new file mode 100644
--- /dev/null
+++ b/src/limits.py
@@ -0,0 +1,3 @@
+def clamp_percentage(value: int) -> int:
+    \"\"\"Clamp an already validated integer percentage.\"\"\"
+    return min(max(value, 0), 100)
diff --git a/tests/test_limits.py b/tests/test_limits.py
new file mode 100644
--- /dev/null
+++ b/tests/test_limits.py
@@ -0,0 +1,6 @@
+from src.limits import clamp_percentage
+
+
+def test_clamp_percentage_boundaries():
+    assert clamp_percentage(-1) == 0
+    assert clamp_percentage(101) == 100
"""

result = post_json(
    "/v1/reviews",
    {
        "repository": "demo/safe-limits",
        "pull_request": 101,
        "mode": "agentic",
        "diff": diff,
    },
    token=session["access_token"],
)

with open("test1_result.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle, ensure_ascii=False, indent=2)

report = result.get("report") or {}
findings = report.get("findings") or []
print("\n安全案例审查完成")
print("任务 ID：", result.get("task_id"))
print("任务状态：", result.get("state"))
print("风险等级：", report.get("risk"))
print("报告摘要：", report.get("summary"))
print("Finding 数量：", len(findings))
for finding in findings:
    print(
        f"- [{finding.get('severity')}] {finding.get('rule_id')} "
        f"{finding.get('path')}:{finding.get('line')} {finding.get('title')}"
    )
print("\n预期：0 个 Finding，风险等级 low")
print("完整结果已保存到 test1_result.json")
