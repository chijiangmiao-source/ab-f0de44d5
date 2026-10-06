"""持久化层：授权族、凭证代次与轮换幂等记录。

所有推进操作都在单条 SQLite 事务内完成（BEGIN IMMEDIATE 取写锁），
因此同标识并发轮换只会有一个胜出者，二者随后读到同一结果；
事务提交即落盘（synchronous=FULL），重启后可凭原轮换标识完整恢复。

每个代次的凭证单独成行，故每一张“后继凭证”的可用性都能独立追踪：
整族撤销时逐代作废，重放历史轮换时精确呈现该后继当前是否仍可用。
"""

from __future__ import annotations

import os
import sqlite3
import threading
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    family_id        TEXT PRIMARY KEY,
    terminal_id      TEXT NOT NULL,
    created_at       REAL NOT NULL,
    revoked          INTEGER NOT NULL DEFAULT 0,
    revoke_reason    TEXT
);
CREATE TABLE IF NOT EXISTS credentials (
    family_id   TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    secret      TEXT NOT NULL,
    usable      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (family_id, generation),
    FOREIGN KEY (family_id) REFERENCES families(family_id)
);
CREATE TABLE IF NOT EXISTS rotations (
    family_id        TEXT NOT NULL,
    old_secret       TEXT NOT NULL,
    rotation_id      TEXT NOT NULL,
    new_secret       TEXT NOT NULL,
    generation       INTEGER NOT NULL,
    created_at       REAL NOT NULL,
    PRIMARY KEY (family_id, old_secret, rotation_id)
);
"""


class NotFound(Exception):
    """授权族不存在。"""


class Revoked(Exception):
    """授权族已撤销。"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(SCHEMA)

    # ---- 基础查询 ----------------------------------------------------

    def get_family(self, family_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM families WHERE family_id=?", (family_id,)
        )
        return cur.fetchone()

    def current_credential(self, family_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM credentials WHERE family_id=? "
            "ORDER BY generation DESC LIMIT 1",
            (family_id,),
        )
        return cur.fetchone()

    # ---- 写操作 ------------------------------------------------------

    def create_family(self, family_id: str, terminal_id: str, secret: str,
                      now: float) -> None:
        with self._lock, self._conn:
            exists = self._conn.execute(
                "SELECT 1 FROM families WHERE family_id=?", (family_id,)
            ).fetchone()
            if exists:
                raise ValueError(f"family already exists: {family_id}")
            self._conn.execute(
                "INSERT INTO families(family_id, terminal_id, created_at) "
                "VALUES(?,?,?)",
                (family_id, terminal_id, now),
            )
            self._conn.execute(
                "INSERT INTO credentials(family_id, generation, secret) "
                "VALUES(?,0,?)",
                (family_id, secret),
            )

    def rotate(self, family_id: str, old_secret: str, rotation_id: str,
               new_secret_proposal: str | None, now: float) -> dict:
        """凭旧凭证与稳定轮换标识推进代次。

        ``new_secret_proposal`` 仅在首次接受时由调用方传入；重放时忽略，
        以保证“同一结果”不依赖客户端重传的新凭证内容。

        返回 dict，其中 ``outcome`` 为:
          * ``accepted``  —— 首次成功，新凭证唯一、代次 +1、仍可用；
          * ``replayed``  —— 同旧凭证+同标识重传（含重启后/并发落败者），
                              返回与首次完全一致的后继凭证与代次；
          * ``revoked``   —— 授权族已撤销（异标识重放已轮换旧凭证等）。
        """
        with self._lock:
            tx = self._conn  # BEGIN IMMEDIATE 串行化同进程/跨进程写者
            tx.execute("BEGIN IMMEDIATE")
            try:
                fam = tx.execute(
                    "SELECT * FROM families WHERE family_id=?", (family_id,)
                ).fetchone()
                if fam is None:
                    raise NotFound(family_id)

                prior = tx.execute(
                    "SELECT * FROM rotations "
                    "WHERE family_id=? AND old_secret=? AND rotation_id=?",
                    (family_id, old_secret, rotation_id),
                ).fetchone()
                if prior is not None:
                    # 同标识重传：后继凭证与代次恒定；usable 反映该后继
                    # 凭证当前状态（可能已被整族撤销连带作废）。
                    succ = tx.execute(
                        "SELECT usable FROM credentials "
                        "WHERE family_id=? AND generation=?",
                        (family_id, prior["generation"]),
                    ).fetchone()
                    tx.commit()
                    return {
                        "outcome": "replayed",
                        "family_id": family_id,
                        "terminal_id": fam["terminal_id"],
                        "rotation_id": rotation_id,
                        "new_credential": prior["new_secret"],
                        "generation": prior["generation"],
                        "usable": bool(succ and succ["usable"]),
                    }

                if fam["revoked"]:
                    raise Revoked(fam["revoke_reason"] or "revoked")

                cur_row = tx.execute(
                    "SELECT * FROM credentials WHERE family_id=? "
                    "ORDER BY generation DESC LIMIT 1",
                    (family_id,),
                ).fetchone()

                if (cur_row is None or not cur_row["usable"]
                        or cur_row["secret"] != old_secret):
                    # 旧凭证已轮换 / 已作废，而轮换标识是新的：
                    # 撤销整族，并连带作废此前发出的全部后继凭证。
                    reason = (
                        "rotated credential reused with a new rotation id"
                    )
                    tx.execute(
                        "UPDATE families SET revoked=1, revoke_reason=? "
                        "WHERE family_id=?",
                        (reason, family_id),
                    )
                    tx.execute(
                        "UPDATE credentials SET usable=0 WHERE family_id=?",
                        (family_id,),
                    )
                    tx.commit()
                    raise Revoked(reason)

                new_secret = new_secret_proposal or _fresh_secret()
                generation = cur_row["generation"] + 1
                tx.execute(
                    "INSERT INTO credentials(family_id, generation, secret) "
                    "VALUES(?,?,?)",
                    (family_id, generation, new_secret),
                )
                tx.execute(
                    "INSERT INTO rotations(family_id, old_secret, "
                    "rotation_id, new_secret, generation, created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (family_id, old_secret, rotation_id, new_secret,
                     generation, now),
                )
                tx.commit()
                return {
                    "outcome": "accepted",
                    "family_id": family_id,
                    "terminal_id": fam["terminal_id"],
                    "rotation_id": rotation_id,
                    "new_credential": new_secret,
                    "generation": generation,
                    "usable": True,
                }
            except Revoked:
                raise
            except Exception:
                tx.rollback()
                raise

    def close(self) -> None:
        self._conn.close()


def _fresh_secret() -> str:
    import secrets

    return "cred-" + secrets.token_hex(24)
