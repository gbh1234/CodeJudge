"""Submit an intentionally vulnerable PR diff to EvoAgent."""
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

# 风险案例：外部路径被拼进 Shell 命令，并显式使用 shell=True。
diff = """diff --git a/backup.py b/backup.py
new file mode 100644
--- /dev/null
+++ b/backup.py
@@ -0,0 +1,5 @@
+import subprocess
+
+
+def create_backup(user_path: str) -> None:
+    subprocess.run(f\"tar -czf backup.tgz {user_path}\", shell=True, check=True)
"""

result = post_json(
    "/v1/reviews",
    {
        "repository": "demo/unsafe-backup",
        "pull_request": 102,
        "mode": "agentic",
        "diff": diff,
    },
    token=session["access_token"],
)

with open("test2_result.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle, ensure_ascii=False, indent=2)

report = result.get("report") or {}
findings = report.get("findings") or []
print("\n风险案例审查完成")
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
print("\n预期：至少包含 SEC-SUBPROCESS-SHELL，风险等级 high")
print("完整结果已保存到 test2_result.json")
