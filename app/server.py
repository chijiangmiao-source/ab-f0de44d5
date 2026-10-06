"""HTTP 服务：授权族创建、幂等凭证轮换、健康检查与操作员页面。

环境变量：
  HOST                监听地址，默认 0.0.0.0
  PORT                监听端口（同时也是 Compose 映射到宿主机的端口），
                      默认 8080
  DB_PATH             SQLite 路径，默认 /data/groundstation.db
  RESPONSE_FAULT      置 1 时，轮换请求“提交后丢弃响应”：
                      事务已持久化，但 TCP 连接直接关闭、不回任何 HTTP 响应。
                      每个进程只触发一次，用于模拟断回应故障后的恢复。
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .db import NotFound, Revoked, Store

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

_FAULT_USED = False


def _fresh_credential() -> str:
    return "cred-" + secrets.token_hex(24)


class Handler(BaseHTTPRequestHandler):
    server_version = "DeepSpaceAuth/1.0"

    # ---- 工具 --------------------------------------------------------

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            data = {}
        return data if isinstance(data, dict) else {}

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"[{self.log_date_time_string()}] {fmt % args}", flush=True)

    # ---- 路由 --------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"status": "ok", "time": time.time()})
            return
        if path == "/api/families":
            self._list_families()
            return
        if path.startswith("/api/families/"):
            self._family_status(path.rsplit("/", 1)[-1])
            return
        if path in ("/", "/index.html"):
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/families":
            self._create_family()
            return
        if path == "/api/rotate":
            self._rotate()
            return
        self._json(404, {"error": "not found"})

    # ---- 业务 --------------------------------------------------------

    def _list_families(self) -> None:
        rows = self.server.store._conn.execute(  # noqa: SLF001
            "SELECT f.family_id, f.terminal_id, f.revoked, f.revoke_reason, "
            "c.generation, c.usable FROM families f "
            "LEFT JOIN credentials c ON c.family_id=f.family_id "
            "AND c.generation=(SELECT MAX(generation) FROM credentials "
            "WHERE family_id=f.family_id) ORDER BY f.created_at"
        ).fetchall()
        self._json(200, {"families": [dict(r) for r in rows]})

    def _family_status(self, family_id: str) -> None:
        fam = self.server.store.get_family(family_id)
        if fam is None:
            self._json(404, {"error": "family not found"})
            return
        cred = self.server.store.current_credential(family_id)
        self._json(200, {
            "family_id": fam["family_id"],
            "terminal_id": fam["terminal_id"],
            "revoked": bool(fam["revoked"]),
            "revoke_reason": fam["revoke_reason"],
            "generation": cred["generation"] if cred else None,
            "usable": bool(cred and cred["usable"]),
        })

    def _create_family(self) -> None:
        data = self._read_json()
        terminal_id = str(data.get("terminal_id") or "").strip()
        if not terminal_id:
            self._json(400, {"error": "terminal_id is required"})
            return
        family_id = str(data.get("family_id") or "").strip() \
            or "fam-" + secrets.token_hex(8)
        bootstrap = _fresh_credential()
        try:
            self.server.store.create_family(family_id, terminal_id, bootstrap,
                                     time.time())
        except ValueError as exc:
            self._json(409, {"error": str(exc)})
            return
        self._json(201, {
            "outcome": "created",
            "family_id": family_id,
            "terminal_id": terminal_id,
            "credential": bootstrap,  # 仅在创建时展示一次
            "generation": 0,
            "usable": True,
        })

    def _rotate(self) -> None:
        global _FAULT_USED
        data = self._read_json()
        family_id = str(data.get("family_id") or "").strip()
        old_secret = str(data.get("old_credential") or "").strip()
        rotation_id = str(data.get("rotation_id") or "").strip()
        if not (family_id and old_secret and rotation_id):
            self._json(400, {"error": "family_id, old_credential and "
                                      "rotation_id are required"})
            return
        try:
            result = self.server.store.rotate(
                family_id, old_secret, rotation_id,
                new_secret_proposal=None, now=time.time(),
            )
        except NotFound:
            self._json(404, {"error": "family not found"})
            return
        except Revoked as exc:
            fam = self.server.store.get_family(family_id)
            self._json(409, {
                "outcome": "revoked",
                "family_id": family_id,
                "revoke_reason": exc.reason,
                "terminal_id": fam["terminal_id"] if fam else None,
            })
            return

        # 提交后断回应故障：结果已持久化，但客户端收不到响应。
        if os.environ.get("RESPONSE_FAULT") == "1" and not _FAULT_USED:
            _FAULT_USED = True
            self.log_message("RESPONSE_FAULT: rotation %s committed, "
                             "dropping response (connection reset)",
                             rotation_id)
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return

        self._json(200, result)

    # ---- 静态资源 ----------------------------------------------------

    def _serve_static(self, name: str, content_type: str) -> None:
        path = os.path.join(STATIC_DIR, name)
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._json(404, {"error": "page not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    store = Store(db_path)
    server = ThreadingHTTPServer((host, port), Handler)
    server.store = store  # type: ignore[attr-defined]
    return server


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "/data/groundstation.db")
    server = build_server(host, port, db_path)
    print(f"ground-station auth service on {host}:{port} db={db_path} "
          f"response_fault={os.environ.get('RESPONSE_FAULT', '0')}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.close()  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
