"""生成修复的确定性验证门禁：语法、Token 化、编译和测试必须先通过。"""
import os
import shlex
import subprocess
import tempfile
import time
import zipfile
import io
import tokenize
from io import BytesIO
from typing import Dict, Iterable


class RepairVerifier:
    """在临时工作区验证候选文件，避免未验证修改直接进入修复分支。"""
    def __init__(self, test_command: str = "", timeout_seconds: int = 120):
        self.test_command = test_command
        self.timeout_seconds = timeout_seconds

    def verify_contents(self, files: Dict[str, str]) -> dict:
        """对内存中的文件执行快速语法检查，不产生仓库副作用。"""
        started = time.monotonic()
        checks = []
        for path, content in files.items():
            if path.endswith(".py"):
                try:
                    compile(content, path, "exec")
                    checks.append({"name": "compile:%s" % path, "passed": True})
                    list(tokenize.generate_tokens(io.StringIO(content).readline))
                    checks.append({"name": "cst-tokenize:%s" % path, "passed": True})
                except SyntaxError as exc:
                    checks.append({
                        "name": "compile:%s" % path, "passed": False,
                        "detail": "%s:%s: %s" % (path, exc.lineno, exc.msg),
                    })
                except (tokenize.TokenError, IndentationError) as exc:
                    checks.append({
                        "name": "cst-tokenize:%s" % path, "passed": False,
                        "detail": str(exc)[:1000],
                    })
        return {
            "passed": all(item["passed"] for item in checks),
            "checks": checks,
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def verify_worktree(self, root: str) -> dict:
        """在指定临时工作树执行项目测试命令，并记录超时与输出。"""
        if not self.test_command:
            return {"passed": True, "checks": [], "note": "No repository test command configured."}
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            raise ValueError("verification worktree does not exist")
        command = shlex.split(self.test_command, posix=os.name != "nt")
        started = time.monotonic()
        env = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TMP", "TEMP"}
        }
        with tempfile.TemporaryDirectory(prefix="evoagent-verify-") as temp:
            env["TMPDIR"] = temp
            try:
                result = subprocess.run(
                    command, cwd=root, env=env, text=True, capture_output=True,
                    timeout=self.timeout_seconds, check=False,
                )
                passed = result.returncode == 0
                detail = (result.stdout + "\n" + result.stderr)[-8000:]
            except subprocess.TimeoutExpired as exc:
                passed = False
                detail = "verification exceeded %d seconds" % self.timeout_seconds
        return {
            "passed": passed,
            "checks": [{"name": "repository-tests", "passed": passed, "detail": detail}],
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def verify_archive(self, archive: bytes, files: Dict[str, str]) -> dict:
        """安全解压仓库快照、覆盖候选文件，再进行完整验证。"""
        """Verify changed files inside an isolated copy of the complete repository."""
        with tempfile.TemporaryDirectory(prefix="evoagent-repair-") as root:
            with zipfile.ZipFile(BytesIO(archive)) as bundle:
                for member in bundle.infolist():
                    normalized = os.path.normpath(member.filename).replace("\\", "/")
                    if normalized.startswith("../") or normalized.startswith("/"):
                        raise ValueError("repository archive contains an unsafe path")
                    target = os.path.abspath(os.path.join(root, normalized))
                    if not target.startswith(os.path.abspath(root) + os.sep):
                        raise ValueError("repository archive escapes the sandbox")
                    bundle.extract(member, root)
            entries = [item for item in os.scandir(root) if item.is_dir()]
            worktree = entries[0].path if len(entries) == 1 else root
            for path, content in files.items():
                target = os.path.abspath(os.path.join(worktree, path))
                if not target.startswith(os.path.abspath(worktree) + os.sep):
                    raise ValueError("repair path escapes the repository")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="") as handle:
                    handle.write(content)
            compile_result = self.verify_contents(files)
            if not compile_result["passed"]:
                return compile_result
            test_result = self.verify_worktree(worktree)
            checks = compile_result["checks"] + test_result["checks"]
            return {
                "passed": compile_result["passed"] and test_result["passed"],
                "checks": checks,
                "duration_seconds": round(
                    compile_result.get("duration_seconds", 0)
                    + test_result.get("duration_seconds", 0), 4
                ),
            }

    @staticmethod
    def compare(before: dict, after: dict) -> dict:
        """比较修复前后结果，确认没有引入新的验证失败。"""
        before_tests = [
            item for item in before.get("checks", [])
            if item.get("name") == "repository-tests"
        ]
        after_tests = [
            item for item in after.get("checks", [])
            if item.get("name") == "repository-tests"
        ]
        passed = bool(
            before.get("passed") and after.get("passed")
            and before_tests and after_tests
            and all(item.get("passed") for item in after_tests)
        )
        return {
            "passed": passed,
            "baseline_passed": bool(before.get("passed")),
            "patched_passed": bool(after.get("passed")),
            "test_evidence_present": bool(before_tests and after_tests),
            "behavioral_regression_detected": bool(
                before.get("passed") and not after.get("passed")
            ),
        }
