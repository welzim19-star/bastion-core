"""
Bastion Audit v2.0 Enterprise - Thread-Safe SQLite Storage Adapter
Persistência transacional com WAL mode, isolamento por thread e integridade ACID.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, List, Optional, Set

from core.models import Device, DeviceStatus


class SQLiteDeviceRepository:
    """Repositório de dispositivos e inventário de rede thread-safe sobre SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Obtém uma conexão SQLite dedicada para a thread atual com WAL habilitado."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                self.db_path,
                timeout=10.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Otimizações de concorrência Enterprise
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Gerenciador de contexto para transações ACID seguras."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_db(self):
        """Inicializa tabelas e índices se não existirem."""
        with self.transaction() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac              TEXT PRIMARY KEY,
                    ip               TEXT,
                    vendor           TEXT,
                    first_seen       TEXT,
                    last_seen        TEXT,
                    alert_sent       TEXT,
                    status           TEXT DEFAULT 'unknown',
                    hostname         TEXT,
                    device_type      TEXT,
                    os_hint          TEXT,
                    is_mac_randomized INTEGER DEFAULT 0,
                    confidence_score INTEGER DEFAULT 0,
                    evidence         TEXT,
                    metadata         TEXT
                );
            """
            )
            # Schema Migration automática (bases legadas v1.7 e v2.0)
            cur.execute("PRAGMA table_info(devices);")
            existing_cols = {row["name"] for row in cur.fetchall()}
            migrations = [
                ("ip",               "TEXT"),
                ("hostname",         "TEXT"),
                ("metadata",         "TEXT"),
                ("device_type",      "TEXT"),
                ("os_hint",          "TEXT"),
                ("is_mac_randomized","INTEGER DEFAULT 0"),
                ("confidence_score", "INTEGER DEFAULT 0"),
                ("evidence",         "TEXT"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    cur.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def};")

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);"
            )

    def upsert_device(self, device: Device) -> bool:
        """Insere ou atualiza o dispositivo no inventário. Retorna True se for novo."""
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self.transaction() as cur:
            cur.execute("SELECT first_seen FROM devices WHERE mac = ?", (device.mac,))
            row = cur.fetchone()
            is_new = row is None

            first_seen = row["first_seen"] if row else (device.first_seen or now)
            last_seen = now

            cur.execute(
                """
                INSERT INTO devices (mac, ip, vendor, first_seen, last_seen, status, hostname,
                                     device_type, os_hint, is_mac_randomized, confidence_score, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    vendor = CASE WHEN excluded.vendor != 'Fabricante desconhecido' THEN excluded.vendor ELSE devices.vendor END,
                    last_seen = excluded.last_seen,
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    device_type = COALESCE(excluded.device_type, devices.device_type),
                    os_hint = COALESCE(excluded.os_hint, devices.os_hint),
                    is_mac_randomized = excluded.is_mac_randomized,
                    confidence_score = CASE WHEN excluded.confidence_score > devices.confidence_score THEN excluded.confidence_score ELSE devices.confidence_score END,
                    evidence = COALESCE(excluded.evidence, devices.evidence)
            """,
                (
                    device.mac,
                    device.ip,
                    device.vendor,
                    first_seen,
                    last_seen,
                    device.status.value,
                    device.hostname,
                    device.metadata.get("device_type") if device.metadata else None,
                    device.metadata.get("os_hint") if device.metadata else None,
                    1 if device.metadata and device.metadata.get("is_mac_randomized") else 0,
                    device.metadata.get("confidence_score", 0) if device.metadata else 0,
                    device.metadata.get("evidence_json") if device.metadata else None,
                ),
            )
            return is_new

    def get_device(self, mac: str) -> Optional[Device]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
        row = cur.fetchone()
        if not row:
            return None
        return self._row_to_device(row)

    def get_known_macs(self) -> Set[str]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT mac FROM devices")
        return {r["mac"] for r in cur.fetchall()}

    def get_all_devices(self) -> List[Device]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        return [self._row_to_device(r) for r in cur.fetchall()]

    def delete_device(self, mac: str) -> bool:
        """Remove um dispositivo específico do inventário."""
        with self.transaction() as cur:
            cur.execute("DELETE FROM devices WHERE mac = ?", (mac,))
            return cur.rowcount > 0

    def purge_legacy_devices(self) -> int:
        """Expurga dispositivos legados com IP 0.0.0.0 ou endereços multicast IEEE."""
        with self.transaction() as cur:
            cur.execute(
                """
                DELETE FROM devices 
                WHERE ip = '0.0.0.0' 
                   OR ip = '' 
                   OR ip IS NULL
                   OR mac LIKE '01:00:5e%'
                   OR mac LIKE '33:33%'
                   OR mac = 'ff:ff:ff:ff:ff:ff'
                """
            )
            return cur.rowcount

    def mark_alert_sent(self, mac: str):
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self.transaction() as cur:
            cur.execute("UPDATE devices SET alert_sent = ? WHERE mac = ?", (now, mac))

    def should_send_alert(self, mac: str, dedup_hours: int = 24) -> bool:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT alert_sent, status FROM devices WHERE mac = ?", (mac,))
        row = cur.fetchone()
        if not row:
            return True
        # Se já é autorizado formalmente, não alerta
        if row["status"] == DeviceStatus.AUTHORIZED.value:
            return False
        alert_sent = row["alert_sent"]
        if not alert_sent:
            return True
        try:
            last = datetime.fromisoformat(alert_sent)
            return datetime.now().astimezone() - last > timedelta(hours=dedup_hours)
        except Exception:
            return True

    def establish_baseline(self, devices: List[Device]):
        """Define o inventário atual como baseline autorizada de segurança."""
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self.transaction() as cur:
            for d in devices:
                cur.execute(
                    """
                    INSERT INTO devices (mac, ip, vendor, first_seen, last_seen, status, hostname,
                                         device_type, os_hint, is_mac_randomized, confidence_score, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        ip = excluded.ip,
                        last_seen = excluded.last_seen,
                        status = excluded.status,
                        device_type = COALESCE(excluded.device_type, devices.device_type),
                        os_hint = COALESCE(excluded.os_hint, devices.os_hint),
                        confidence_score = excluded.confidence_score
                """,
                    (
                        d.mac,
                        d.ip,
                        d.vendor,
                        now,
                        now,
                        DeviceStatus.AUTHORIZED.value,
                        d.hostname,
                        d.metadata.get("device_type") if d.metadata else None,
                        d.metadata.get("os_hint") if d.metadata else None,
                        1 if d.metadata and d.metadata.get("is_mac_randomized") else 0,
                        d.metadata.get("confidence_score", 0) if d.metadata else 0,
                        d.metadata.get("evidence_json") if d.metadata else None,
                    ),
                )

    def get_audit_summary(self, days: int = 7) -> Dict[str, Any]:
        conn = self._get_connection()
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        unknown = cur.execute(
            "SELECT COUNT(*) FROM devices WHERE status = ?", (DeviceStatus.UNKNOWN.value,)
        ).fetchone()[0]
        authorized = cur.execute(
            "SELECT COUNT(*) FROM devices WHERE status = ?", (DeviceStatus.AUTHORIZED.value,)
        ).fetchone()[0]

        cur.execute(
            """
            SELECT mac, ip, vendor, first_seen, last_seen, status
            FROM devices
            WHERE first_seen >= datetime('now', ?)
            ORDER BY first_seen DESC
            LIMIT 15
        """,
            (f"-{days} days",),
        )
        recent_rows = [dict(r) for r in cur.fetchall()]

        return {
            "total_devices": total,
            "authorized_devices": authorized,
            "unknown_devices": unknown,
            "recent_new_devices": recent_rows,
        }

    def _row_to_device(self, row: sqlite3.Row) -> Device:
        import json as _json
        status_val = row["status"] or "unknown"
        try:
            status = DeviceStatus(status_val)
        except ValueError:
            status = DeviceStatus.UNKNOWN

        # Reconstituição dos metadados de intelligence do banco
        evidence_list = []
        if row["evidence"]:
            try:
                evidence_list = _json.loads(row["evidence"])
            except Exception:
                evidence_list = [row["evidence"]]

        metadata = {
            "device_type": row["device_type"] or "",
            "os_hint": row["os_hint"] or "",
            "is_mac_randomized": bool(row["is_mac_randomized"]),
            "confidence_score": row["confidence_score"] or 0,
            "evidence": evidence_list,
        }

        return Device(
            mac=row["mac"],
            ip=row["ip"] or "0.0.0.0",
            vendor=row["vendor"] or "Fabricante desconhecido",
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            alert_sent=row["alert_sent"],
            status=status,
            hostname=row["hostname"],
            metadata=metadata,
        )
