"""Add the safe test1 diff to EvoAgent's validation dataset."""

import getpass
import json
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = "http://127.0.0.1:8080"
CASE_NAME = "clean-clamp-validated-integer"


def request_json(path, method="GET", payload=None, token=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        BASE_URL + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


password = getpass.getpass("管理员密码：")
session = request_json(
    "/v1/auth/login",
    method="POST",
    payload={"username": "admin", "password": password},
)
token = session["access_token"]
print("登录成功，租户：", session["tenant_id"])

existing = request_json(
    "/v1/evaluation/cases?" + urllib.parse.urlencode({"split": "validation"}),
    token=token,
)
cases = existing.get("cases", []) if isinstance(existing, dict) else []
if any(case.get("name") == CASE_NAME for case in cases):
    print(f"Validation 样本已存在：{CASE_NAME}，无需重复添加。")
    raise SystemExit(0)

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

created = request_json(
    "/v1/evaluation/cases",
    method="POST",
    payload={
        "name": CASE_NAME,
        "split": "validation",
        "diff": diff,
        "expected_findings": [],
    },
    token=token,
)

print("Validation 样本添加成功：")
print(json.dumps(created, ensure_ascii=False, indent=2))
print("\n下一步：刷新前端演进实验室，确认 validation_cases 增加 1。")
