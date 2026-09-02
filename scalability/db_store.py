"""
Database-Backed Quarantine & Audit Store.
Provides indexed SQL-backed storage and fast pagination for email quarantine records and audit logs.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class QuarantineRecord:
    msg_id: str
    tenant_id: str
    sender: str
    recipient: str
    subject: str
    verdict: str
    risk_score: float
    status: str          # "pending" | "released" | "rejected" | "expired"
    created_at: float
    raw_payload: str     # JSON string payload


class DatabaseQuarantineStore:
    """High-performance SQLite / SQL indexed database store for quarantine & audit queries."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._shared_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                msg_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                verdict TEXT,
                risk_score REAL,
                status TEXT,
                created_at REAL,
                raw_payload TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tenant_status ON quarantine (tenant_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON quarantine (created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sender ON quarantine (sender)")
        conn.commit()

    def save(self, record_dict: dict) -> str:
        msg_id = record_dict.get("id") or record_dict.get("msg_id") or str(uuid.uuid4())
        rec = QuarantineRecord(
            msg_id=msg_id,
            tenant_id=record_dict.get("tenant_id", "default"),
            sender=record_dict.get("sender", ""),
            recipient=record_dict.get("recipient", ""),
            subject=record_dict.get("subject", ""),
            verdict=record_dict.get("action", record_dict.get("verdict", "quarantine")),
            risk_score=float(record_dict.get("score", record_dict.get("risk_score", 0.0))),
            status=record_dict.get("status", "pending"),
            created_at=record_dict.get("created_at", time.time()),
            raw_payload=json.dumps(record_dict),
        )
        return self.save_record(rec)

    def save_record(self, record: QuarantineRecord) -> str:
        conn = self._get_conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO quarantine
            (msg_id, tenant_id, sender, recipient, subject, verdict, risk_score, status, created_at, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.msg_id,
                record.tenant_id,
                record.sender.lower(),
                record.recipient.lower(),
                record.subject,
                record.verdict,
                record.risk_score,
                record.status,
                record.created_at or time.time(),
                record.raw_payload,
            ),
        )
        conn.commit()
        return record.msg_id

    def get(self, msg_id: str) -> Optional[dict[str, Any]]:
        row = self.get_record(msg_id)
        if not row:
            return None
        res = dict(row)
        res["id"] = res["msg_id"]
        return res

    def get_record(self, msg_id: str) -> Optional[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute("SELECT * FROM quarantine WHERE msg_id = ?", (msg_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def query(
        self,
        tenant_id: str = "",
        status: str = "",
        search_query: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        records = self.search_quarantine(query=search_query, tenant_id=tenant_id, status=status, limit=limit, offset=offset)
        for r in records:
            r["id"] = r["msg_id"]
        return records

    def list_pending(self, tenant_id: str = "", limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self.query(tenant_id=tenant_id, status="pending", limit=limit, offset=offset)

    def search_quarantine(
        self,
        query: str = "",
        tenant_id: str = "",
        status: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions = []
        params = []

        if tenant_id:
            conditions.append("tenant_id = ?")
            params.append(tenant_id)

        if status:
            conditions.append("status = ?")
            params.append(status)

        if query:
            conditions.append("(sender LIKE ? OR recipient LIKE ? OR subject LIKE ?)")
            q_param = f"%{query.lower()}%"
            params.extend([q_param, q_param, q_param])

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM quarantine {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        conn = self._get_conn()
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def update_status(self, msg_id: str, new_status: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute("UPDATE quarantine SET status = ? WHERE msg_id = ?", (new_status, msg_id))
        conn.commit()
        return cur.rowcount > 0


IndexedDatabaseQuarantineStore = DatabaseQuarantineStore
