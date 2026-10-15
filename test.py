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


# 这里输入的是管理员密码，不是 EVOAGENT_AUTH_SECRET
password = getpass.getpass("管理员密码：")

session = post_json(
    "/v1/auth/login",
    {
        "username": "admin",
        "password": password,
    },
)

print("登录成功，租户：", session["tenant_id"])

diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +1,1 @@
+eval(user_input)
"""

result = post_json(
    "/v1/reviews",
    {
        "repository": "demo/api",
        "pull_request": 12,
        "mode": "agentic",
        "diff": diff,
    },
    token=session["access_token"],
)

# 完整结果保存到文件，避免终端输出太多
with open("review_result.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle, ensure_ascii=False, indent=2)

report = result.get("report") or {}

print("\n审查完成")
print("任务 ID：", result.get("task_id"))
print("任务状态：", result.get("state"))
print("风险等级：", report.get("risk"))
print("报告摘要：", report.get("summary"))
print("Finding 数量：", len(report.get("findings") or []))

for finding in report.get("findings") or []:
    print(
        f"- [{finding.get('severity')}] "
        f"{finding.get('rule_id')} "
        f"{finding.get('path')}:{finding.get('line')} "
        f"{finding.get('title')}"
    )

print("\n完整结果已保存到 review_result.json")