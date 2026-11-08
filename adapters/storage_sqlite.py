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
        import json as _json
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self.transaction() as cur:
            # 1. Evita colisão de IP: se outro MAC antigo estava com este mesmo IP, move o antigo para Inativo (0.0.0.0)
            if device.ip and device.ip not in ("0.0.0.0", ""):
                cur.execute(
                    "SELECT mac, metadata FROM devices WHERE ip = ? AND mac != ?",
                    (device.ip, device.mac),
                )
                for stale_row in cur.fetchall():
                    stale_meta = {}
                    if stale_row["metadata"]:
                        try:
                            stale_meta = _json.loads(stale_row["metadata"])
                        except Exception:
                            stale_meta = {}
                    stale_meta["last_known_ip"] = device.ip
                    cur.execute(
                        "UPDATE devices SET ip = '0.0.0.0', metadata = ? WHERE mac = ?",
                        (_json.dumps(stale_meta, ensure_ascii=False), stale_row["mac"]),
                    )

            cur.execute("SELECT first_seen, metadata, device_type, os_hint, hostname FROM devices WHERE mac = ?", (device.mac,))
            row = cur.fetchone()
            is_new = row is None

            first_seen = row["first_seen"] if row else (device.first_seen or now)
            last_seen = now

            existing_meta = {}
            if row and row["metadata"]:
                try:
                    existing_meta = _json.loads(row["metadata"])
                except Exception:
                    existing_meta = {}

            # 2. Se um celular reconectou com novo MAC Aleatório mas informou o MESMO ID único (hostname),
            # herda automaticamente o apelido e modelo personalizados pelo usuário!
            eff_hostname = device.hostname or (row["hostname"] if row else None)
            if eff_hostname and not existing_meta.get("custom_name"):
                cur.execute(
                    "SELECT metadata, device_type, os_hint FROM devices WHERE hostname = ? AND mac != ? ORDER BY last_seen DESC LIMIT 1",
                    (eff_hostname, device.mac),
                )
                prev_id_row = cur.fetchone()
                if prev_id_row and prev_id_row["metadata"]:
                    try:
                        prev_meta = _json.loads(prev_id_row["metadata"])
                        if prev_meta.get("custom_name"):
                            existing_meta["custom_name"] = prev_meta["custom_name"]
                        if prev_meta.get("manual_override") and prev_meta.get("hardware_model"):
                            existing_meta["hardware_model"] = prev_meta["hardware_model"]
                            existing_meta["manual_override"] = True
                    except Exception:
                        pass

            new_meta = dict(existing_meta)
            if device.metadata:
                for k, v in device.metadata.items():
                    if k not in ("evidence_json", "device_type", "os_hint", "is_mac_randomized", "confidence_score") and v is not None:
                        if k == "hardware_model" and existing_meta.get("manual_override") and existing_meta.get("hardware_model"):
                            continue
                        new_meta[k] = v

            # Preserva classificação manual ou mais específica caso o novo scan venha genérico
            incoming_type = device.metadata.get("device_type") if device.metadata else None
            if existing_meta.get("manual_override") and row and row["device_type"]:
                effective_type = row["device_type"]
            elif incoming_type and incoming_type != "Dispositivo Desconhecido":
                effective_type = incoming_type
            elif row and row["device_type"] and row["device_type"] != "Dispositivo Desconhecido":
                effective_type = row["device_type"]
            else:
                effective_type = incoming_type or (row["device_type"] if row else None)

            incoming_os = device.metadata.get("os_hint") if device.metadata else None
            if incoming_os and incoming_os != "Indefinido":
                effective_os = incoming_os
            elif row and row["os_hint"] and row["os_hint"] != "Indefinido":
                effective_os = row["os_hint"]
            else:
                effective_os = incoming_os or (row["os_hint"] if row else None)

            cur.execute(
                """
                INSERT INTO devices (mac, ip, vendor, first_seen, last_seen, status, hostname,
                                     device_type, os_hint, is_mac_randomized, confidence_score, evidence, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = CASE WHEN excluded.ip != '0.0.0.0' AND excluded.ip != '' THEN excluded.ip ELSE devices.ip END,
                    vendor = CASE WHEN excluded.vendor != 'Fabricante desconhecido' THEN excluded.vendor ELSE devices.vendor END,
                    last_seen = excluded.last_seen,
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    device_type = COALESCE(excluded.device_type, devices.device_type),
                    os_hint = COALESCE(excluded.os_hint, devices.os_hint),
                    is_mac_randomized = excluded.is_mac_randomized,
                    confidence_score = CASE WHEN excluded.confidence_score > devices.confidence_score THEN excluded.confidence_score ELSE devices.confidence_score END,
                    evidence = COALESCE(excluded.evidence, devices.evidence),
                    metadata = excluded.metadata
            """,
                (
                    device.mac,
                    device.ip,
                    device.vendor,
                    first_seen,
                    last_seen,
                    device.status.value,
                    device.hostname,
                    effective_type,
                    effective_os,
                    1 if device.metadata and device.metadata.get("is_mac_randomized") else 0,
                    device.metadata.get("confidence_score", 0) if device.metadata else 0,
                    device.metadata.get("evidence_json") if device.metadata else None,
                    _json.dumps(new_meta, ensure_ascii=False),
                ),
            )
            return is_new

    def reconcile_online_devices(self, active_macs: Set[str], max_idle_minutes: int = 45) -> int:
        """
        Move para Inativos (ip = '0.0.0.0') os dispositivos que não estão na tabela ARP atual
        e cujo last_seen já passou de max_idle_minutes, preservando last_known_ip em metadata.
        """
        import json as _json
        now = datetime.now().astimezone()
        moved = 0
        with self.transaction() as cur:
            cur.execute("SELECT mac, ip, last_seen, metadata FROM devices WHERE ip != '0.0.0.0' AND ip != ''")
            rows = cur.fetchall()
            for r in rows:
                mac = r["mac"]
                if mac in active_macs:
                    continue
                is_stale = False
                raw_ts = r["last_seen"] or ""
                if not raw_ts:
                    is_stale = True
                else:
                    try:
                        dt = datetime.fromisoformat(raw_ts)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=now.tzinfo)
                        diff_min = (now - dt).total_seconds() / 60.0
                        if diff_min > max_idle_minutes:
                            is_stale = True
                    except Exception:
                        is_stale = True

                if is_stale:
                    meta = {}
                    if r["metadata"]:
                        try:
                            meta = _json.loads(r["metadata"])
                        except Exception:
                            meta = {}
                    meta["last_known_ip"] = r["ip"]
                    cur.execute(
                        "UPDATE devices SET ip = '0.0.0.0', metadata = ? WHERE mac = ?",
                        (_json.dumps(meta, ensure_ascii=False), mac),
                    )
                    moved += 1
        return moved

    def update_device_metadata(
        self,
        mac: str,
        meta_updates: Dict[str, Any],
        device_type: Optional[str] = None,
        os_hint: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        confidence_score: Optional[int] = None,
        evidence_list: Optional[List[str]] = None,
    ) -> bool:
        """Atualiza metadados avançados, apelido, categoria manual ou resultados de deep scan."""
        import json as _json
        with self.transaction() as cur:
            cur.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cur.fetchone()
            if not row:
                return False

            existing_meta = {}
            if row["metadata"]:
                try:
                    existing_meta = _json.loads(row["metadata"])
                except Exception:
                    existing_meta = {}

            existing_meta.update(meta_updates)

            new_type = device_type if device_type is not None else row["device_type"]
            new_os = os_hint if os_hint is not None else row["os_hint"]
            new_host = hostname if hostname is not None else row["hostname"]
            new_vendor = vendor if vendor is not None else row["vendor"]
            new_conf = confidence_score if confidence_score is not None else row["confidence_score"]
            new_ev = _json.dumps(evidence_list, ensure_ascii=False) if evidence_list is not None else row["evidence"]

            cur.execute(
                """
                UPDATE devices
                SET device_type = ?,
                    os_hint = ?,
                    hostname = ?,
                    vendor = ?,
                    confidence_score = ?,
                    evidence = ?,
                    metadata = ?
                WHERE mac = ?
                """,
                (
                    new_type,
                    new_os,
                    new_host,
                    new_vendor,
                    new_conf,
                    new_ev,
                    _json.dumps(existing_meta, ensure_ascii=False),
                    mac,
                ),
            )
            return True

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

        extra_meta = {}
        if row["metadata"]:
            try:
                extra_meta = _json.loads(row["metadata"])
            except Exception:
                extra_meta = {}

        metadata = {
            **extra_meta,
            "device_type": row["device_type"] or extra_meta.get("device_type") or "",
            "os_hint": row["os_hint"] or extra_meta.get("os_hint") or "",
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
