#!/usr/bin/env python3
"""Compose verify 验收脚本（仅用标准库，容器内无需第三方依赖）。

覆盖验收点：
  1. 代码层：创建授权族 → 接受轮换 → 同标识重放恒定 → 重启（重新打开库）
     后仍取回同一后继凭证且代次不推进；异标识重放撤销整族、后继作废。
  2. HTTP 冒烟：/health、操作员页面可观察标记（接受/重放/已撤销、
     新凭证、代次、可用状态、撤销原因、断回应提示）。
  3. 并发同标识：多个并发相同轮换请求只产生同一后继凭证与同一代次，
     服务重启后重放依旧一致。
  4. 提交后断回应：RESPONSE_FAULT=1 时首次请求收不到响应，重启后凭原
     旧凭证+原轮换标识取回已持久化后继、代次停在 1，且流水线可继续推进。
  5. 异标识重放：已轮换旧凭证配新 rotation_id → 页面/接口呈现撤销原因，
     此前发出的后继凭证随后同样被拒绝。
  6. 若设置 APP_URL（Compose 中为 http://app:8080），对真正运行的
     app 容器再做一轮 API/HTTP 冒烟。

任一断言失败即以非零退出码报告验收结果。
"""

from __future__ import annotations

import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import NotFound, Revoked, Store  # noqa: E402

APP_URL = os.environ.get("APP_URL", "").rstrip("/")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


# --------------------------------------------------------------------------
# HTTP 小工具
# --------------------------------------------------------------------------

def http_call(method: str, url: str, payload: dict | None = None,
              timeout: float = 10.0):
    """返回 (status, headers, body_text)；连接被掐断时抛出底层异常。"""
    parsed = urllib.request.urlparse(url) if hasattr(urllib.request, "urlparse") \
        else __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port,
                                      timeout=timeout)
    try:
        conn.request(method, parsed.path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def http_json(method, url, payload=None, timeout=10.0):
    status, _, text = http_call(method, url, payload, timeout)
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"_raw": text}


def wait_healthy(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, data = http_json("GET", base_url + "/health", timeout=3)
            if status == 200 and data.get("status") == "ok":
                return
        except OSError as exc:  # 服务尚未起来 / 连接被拒
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"service at {base_url} not healthy: {last}")


# --------------------------------------------------------------------------
# 服务子进程（重启 = 杀掉再起，DB 在持久目录上）
# --------------------------------------------------------------------------

class ServerProc:
    def __init__(self, db_path: str, port: int, fault: bool = False):
        self.db_path = db_path
        self.port = port
        self.fault = fault
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "ServerProc":
        env = os.environ.copy()
        env.update({
            "HOST": "127.0.0.1",
            "PORT": str(self.port),
            "DB_PATH": self.db_path,
            "RESPONSE_FAULT": "1" if self.fault else "0",
            "PYTHONPATH": str(ROOT),
        })
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "app.server"],
            cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            wait_healthy(self.url)
        except Exception:
            self.stop()
            raise
        return self

    def stop(self) -> str:
        if not self.proc:
            return ""
        self.proc.terminate()
        try:
            out, _ = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate(timeout=10)
        self.proc = None
        return out or ""

    def restart(self, fault: bool | None = None) -> "ServerProc":
        self.stop()
        if fault is not None:
            self.fault = fault
        return self.start()


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


def create_family(base_url: str) -> dict:
    status, data = http_json("POST", base_url + "/api/families", {
        "terminal_id": unique("term"),
        "family_id": unique("fam"),
    })
    assert status == 201, data
    return data


# --------------------------------------------------------------------------
# 代码层测试
# --------------------------------------------------------------------------

class StoreContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "s.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_accept_then_idempotent_replay_across_restart(self):
        self.store.create_family("fam1", "term1", "old0", 1.0)
        r1 = self.store.rotate("fam1", "old0", "rid-1", None, 2.0)
        self.assertEqual(r1["outcome"], "accepted")
        self.assertEqual(r1["generation"], 1)
        self.assertTrue(r1["usable"])
        new1 = r1["new_credential"]
        self.assertNotEqual(new1, "old0")

        # 同旧凭证+同标识重传 → 完全一致的后继与代次
        r2 = self.store.rotate("fam1", "old0", "rid-1", None, 3.0)
        self.assertEqual(r2["outcome"], "replayed")
        self.assertEqual(r2["new_credential"], new1)
        self.assertEqual(r2["generation"], 1)

        # “服务重启”：重新打开同一持久化文件
        self.store.close()
        self.store = Store(self.db)
        r3 = self.store.rotate("fam1", "old0", "rid-1", None, 4.0)
        self.assertEqual(r3["outcome"], "replayed")
        self.assertEqual(r3["new_credential"], new1)
        self.assertEqual(r3["generation"], 1)

        # 正常链路仍可继续：以新凭证推进到代次 2
        r4 = self.store.rotate("fam1", new1, "rid-2", None, 5.0)
        self.assertEqual(r4["outcome"], "accepted")
        self.assertEqual(r4["generation"], 2)

    def test_different_rotation_id_revokes_family_and_successor(self):
        self.store.create_family("fam2", "term2", "old0", 1.0)
        r1 = self.store.rotate("fam2", "old0", "rid-a", None, 2.0)
        new1 = r1["new_credential"]

        with self.assertRaises(Revoked) as ctx:
            self.store.rotate("fam2", "old0", "rid-DIFFERENT", None, 3.0)
        self.assertIn("rotation id", ctx.exception.reason)

        # 授权族已撤销；此前发出的后继凭证随后同样被拒绝
        with self.assertRaises(Revoked):
            self.store.rotate("fam2", new1, "rid-b", None, 4.0)
        fam = self.store.get_family("fam2")
        self.assertTrue(fam["revoked"])
        self.assertTrue(fam["revoke_reason"])


# --------------------------------------------------------------------------
# HTTP / 页面 / 故障 / 并发测试
# --------------------------------------------------------------------------

PAGE_MARKERS = [
    'data-testid="result-outcome"',
    'data-testid="new-credential"',
    'data-testid="generation"',
    'data-testid="usable"',
    'data-testid="revoke-reason"',
    'data-testid="fault-hint"',
    "接受", "重放", "已撤销", "撤销原因",
]


class HttpAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls.tmp.name) / "http.db")
        cls.port = int(os.environ.get("VERIFY_PORT", "18080"))
        cls.srv = ServerProc(cls.db, cls.port, fault=False).start()
        cls.url = cls.srv.url

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        cls.tmp.cleanup()

    def test_01_health_and_page_observable(self):
        status, data = http_json("GET", self.url + "/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")

        status, _, page = http_call("GET", self.url + "/")
        self.assertEqual(status, 200)
        for marker in PAGE_MARKERS:
            self.assertIn(marker, page, f"页面缺少可观察元素: {marker}")

    def test_02_accept_then_replay_identical(self):
        fam = create_family(self.url)
        rid = unique("rid")
        s1, r1 = http_json("POST", self.url + "/api/rotate", {
            "family_id": fam["family_id"],
            "old_credential": fam["credential"],
            "rotation_id": rid,
        })
        self.assertEqual(s1, 200)
        self.assertEqual(r1["outcome"], "accepted")
        self.assertEqual(r1["generation"], 1)
        self.assertTrue(r1["usable"])
        self.assertTrue(r1["new_credential"])

        s2, r2 = http_json("POST", self.url + "/api/rotate", {
            "family_id": fam["family_id"],
            "old_credential": fam["credential"],
            "rotation_id": rid,
        })
        self.assertEqual(s2, 200)
        self.assertEqual(r2["outcome"], "replayed")
        self.assertEqual(r2["new_credential"], r1["new_credential"])
        self.assertEqual(r2["generation"], 1)


class ConcurrentSameIdTests(unittest.TestCase):
    def test_concurrent_requests_share_one_result(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "cc.db")
        port = int(os.environ.get("VERIFY_PORT_CC", "18081"))
        srv = ServerProc(db, port).start()
        self.addCleanup(srv.stop)
        try:
            fam = create_family(srv.url)
            rid = unique("rid")
            payload = {
                "family_id": fam["family_id"],
                "old_credential": fam["credential"],
                "rotation_id": rid,
            }
            results: list = []
            errors: list = []

            def fire():
                try:
                    results.append(
                        http_json("POST", srv.url + "/api/rotate", payload))
                except OSError as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=fire) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            self.assertFalse(errors, f"并发请求出现连接错误: {errors}")
            self.assertEqual(len(results), 8)
            secrets_seen = {b["new_credential"] for _, b in results}
            gens = {b["generation"] for _, b in results}
            outcomes = sorted(b["outcome"] for _, b in results)
            self.assertEqual(len(secrets_seen), 1, "并发产生了多个后继凭证")
            self.assertEqual(gens, {1}, "代次被并发重复推进")
            self.assertEqual(outcomes.count("accepted"), 1)
            self.assertEqual(outcomes.count("replayed"), 7)

            # 重启后同标识重放：仍是同一结果，代次不推进
            srv.restart()
            status, replay = http_json("POST", srv.url + "/api/rotate",
                                       payload)
            self.assertEqual(status, 200)
            self.assertEqual(replay["outcome"], "replayed")
            self.assertEqual(replay["new_credential"],
                             results[0][1]["new_credential"])
            self.assertEqual(replay["generation"], 1)
        finally:
            pass


class ResponseFaultRecoveryTests(unittest.TestCase):
    def test_commit_then_drop_response_recovers_after_restart(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "fault.db")
        port = int(os.environ.get("VERIFY_PORT_FAULT", "18082"))
        srv = ServerProc(db, port, fault=True).start()
        self.addCleanup(lambda: srv.stop())
        try:
            fam = create_family(srv.url)
            rid = unique("rid")
            payload = {
                "family_id": fam["family_id"],
                "old_credential": fam["credential"],
                "rotation_id": rid,
            }

            # 首次请求：已提交但响应被丢弃，客户端只看到连接中断/空响应
            failure = None
            try:
                status, _, text = http_call(
                    "POST", srv.url + "/api/rotate", payload, timeout=5)
                # 即便客户端库把 RST 表现为空响应，也不允许拿到 2xx
                self.assertNotEqual(status, 200,
                                    f"故障下不应返回成功响应: {status} {text}")
            except (OSError, http.client.HTTPException) as exc:
                failure = exc
            self.assertIsNotNone(failure, "断回应故障未生效")

            # 重启服务（关闭故障开关）后原样重传
            srv.restart(fault=False)
            status, rec = http_json("POST", srv.url + "/api/rotate", payload)
            self.assertEqual(status, 200)
            self.assertEqual(rec["outcome"], "replayed",
                             "恢复重传必须识别为幂等重放而非重新轮换")
            self.assertEqual(rec["generation"], 1, "恢复时代次不得重复推进")
            self.assertTrue(rec["new_credential"])
            self.assertTrue(rec["usable"])

            # 状态面：代次停在 1；随后用恢复出的后继可继续推进到 2
            status, st = http_json(
                "GET", f"{srv.url}/api/families/{fam['family_id']}")
            self.assertEqual(status, 200)
            self.assertEqual(st["generation"], 1)
            self.assertFalse(st["revoked"])

            status, nxt = http_json("POST", srv.url + "/api/rotate", {
                "family_id": fam["family_id"],
                "old_credential": rec["new_credential"],
                "rotation_id": unique("rid"),
            })
            self.assertEqual(status, 200)
            self.assertEqual(nxt["outcome"], "accepted")
            self.assertEqual(nxt["generation"], 2)
        finally:
            pass


class DifferentRotationIdTests(unittest.TestCase):
    def test_new_rotation_id_on_rotated_credential_revokes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "rev.db")
        port = int(os.environ.get("VERIFY_PORT_REV", "18083"))
        srv = ServerProc(db, port).start()
        self.addCleanup(srv.stop)
        try:
            fam = create_family(srv.url)
            status, r1 = http_json("POST", srv.url + "/api/rotate", {
                "family_id": fam["family_id"],
                "old_credential": fam["credential"],
                "rotation_id": unique("rid"),
            })
            self.assertEqual(status, 200)
            self.assertEqual(r1["outcome"], "accepted")
            successor = r1["new_credential"]

            # 以“不同轮换标识”再次使用已轮换的旧凭证 → 撤销
            status, rev = http_json("POST", srv.url + "/api/rotate", {
                "family_id": fam["family_id"],
                "old_credential": fam["credential"],
                "rotation_id": unique("rot-different"),
            })
            self.assertEqual(status, 409)
            self.assertEqual(rev["outcome"], "revoked")
            self.assertTrue(rev["revoke_reason"], "必须给出授权族撤销原因")

            # 页面状态查询同样呈现撤销原因
            status, st = http_json(
                "GET", f"{srv.url}/api/families/{fam['family_id']}")
            self.assertEqual(status, 200)
            self.assertTrue(st["revoked"])
            self.assertTrue(st["revoke_reason"])
            self.assertFalse(st["usable"])

            # 此前发出的后继凭证随后同样被拒绝
            status, rev2 = http_json("POST", srv.url + "/api/rotate", {
                "family_id": fam["family_id"],
                "old_credential": successor,
                "rotation_id": unique("rid"),
            })
            self.assertEqual(status, 409)
            self.assertEqual(rev2["outcome"], "revoked")
            self.assertTrue(rev2["revoke_reason"])
        finally:
            pass


@unittest.skipUnless(APP_URL, "未设置 APP_URL：跳过 Compose app 容器冒烟")
class ComposeAppSmokeTests(unittest.TestCase):
    def test_running_app_service_smoke(self):
        wait_healthy(APP_URL)
        status, data = http_json("GET", APP_URL + "/health")
        self.assertEqual((status, data["status"]), (200, "ok"))

        status, _, page = http_call("GET", APP_URL + "/")
        self.assertEqual(status, 200)
        self.assertIn('data-testid="result-outcome"', page)

        fam = create_family(APP_URL)
        rid = unique("rid")
        status, r1 = http_json("POST", APP_URL + "/api/rotate", {
            "family_id": fam["family_id"],
            "old_credential": fam["credential"],
            "rotation_id": rid,
        })
        self.assertEqual(status, 200)
        self.assertEqual(r1["outcome"], "accepted")
        self.assertEqual(r1["generation"], 1)

        status, r2 = http_json("POST", APP_URL + "/api/rotate", {
            "family_id": fam["family_id"],
            "old_credential": fam["credential"],
            "rotation_id": rid,
        })
        self.assertEqual(status, 200)
        self.assertEqual(r2["outcome"], "replayed")
        self.assertEqual(r2["new_credential"], r1["new_credential"])
        self.assertEqual(r2["generation"], 1)


def main() -> int:
    print("=" * 72)
    print("深空地面站授权族轮换 · verify 验收")
    print(f"APP_URL = {APP_URL or '(未设置，仅执行本地子进程验收)'}")
    print("=" * 72, flush=True)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("\n✅ 验收通过：断回应恢复、并发同标识、异标识重放、"
              "页面可观察结果与 HTTP 冒烟全部通过。")
        return 0
    print("\n❌ 验收失败：存在未通过的断言，请查看上方输出。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
