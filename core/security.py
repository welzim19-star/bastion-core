"""
Bastion Audit v2.0 Enterprise - Security & Cryptographic Audit Ledger
Implementação de Trilha de Auditoria Imutável (SHA-256 Chained Hash) em conformidade BACEN/ISO 27001.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .models import AuditEvent

_MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
_IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def sanitize_mac(raw_mac: str) -> Optional[str]:
    """Sanitiza e normaliza endereço MAC em formato padrão 'aa:bb:cc:dd:ee:ff'."""
    if not raw_mac:
        return None
    cleaned = raw_mac.strip().lower().replace("-", ":")
    if _MAC_REGEX.match(cleaned):
        return cleaned
    return None


def sanitize_ip(raw_ip: str) -> Optional[str]:
    """Valida endereço IPv4 decimal com pontos."""
    if not raw_ip:
        return None
    cleaned = raw_ip.strip()
    if _IP_REGEX.match(cleaned):
        parts = cleaned.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return cleaned
    return None


def compute_event_hash(
    event_id: str,
    timestamp: str,
    event_type: str,
    payload: Dict[str, Any],
    previous_hash: str,
) -> str:
    """Calcula hash criptográfico SHA-256 canônico encadeado."""
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    raw_str = f"{event_id}|{timestamp}|{event_type}|{canonical_payload}|{previous_hash}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


class AuditLedger:
    """
    Trilha de auditoria imutável (Append-Only Ledger com encadeamento de hashes SHA-256).
    Qualquer tentativa de adulterar linhas históricas quebra a verificação da cadeia.
    """

    def __init__(self, ledger_file_path: str):
        self.ledger_file_path = ledger_file_path
        self._lock = threading.Lock()
        self._last_hash = _GENESIS_HASH
        os.makedirs(os.path.dirname(os.path.abspath(self.ledger_file_path)), exist_ok=True)
        self._load_or_init()

    def _load_or_init(self):
        with self._lock:
            if not os.path.exists(self.ledger_file_path) or os.path.getsize(self.ledger_file_path) == 0:
                self._last_hash = _GENESIS_HASH
                return

            last_valid_hash = _GENESIS_HASH
            with open(self.ledger_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        last_valid_hash = entry.get("entry_hash", last_valid_hash)
                    except Exception:
                        pass
            self._last_hash = last_valid_hash

    def record_event(
        self,
        event_type: str,
        source: str,
        severity: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        """Gera, encadeia e persiste um novo evento auditável."""
        with self._lock:
            event_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat(timespec="microseconds")
            previous_hash = self._last_hash
            entry_hash = compute_event_hash(
                event_id=event_id,
                timestamp=timestamp,
                event_type=event_type,
                payload=payload,
                previous_hash=previous_hash,
            )

            event = AuditEvent(
                event_id=event_id,
                timestamp=timestamp,
                event_type=event_type,
                source=source,
                severity=severity,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
            )

            with open(self.ledger_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

            self._last_hash = entry_hash
            return event

    def verify_integrity(self) -> Tuple[bool, Optional[str], int]:
        """
        Verifica a integridade completa do ledger.
        Retorna (é_valido, mensagem_de_erro, total_entradas_verificadas).
        """
        with self._lock:
            if not os.path.exists(self.ledger_file_path):
                return True, "Ledger vazio (arquivo inexistente)", 0

            expected_prev = _GENESIS_HASH
            count = 0

            with open(self.ledger_file_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    count += 1
                    try:
                        data = json.loads(line)
                    except Exception as e:
                        return False, f"Linha {idx} com JSON inválido: {e}", count

                    event_id = data.get("event_id")
                    timestamp = data.get("timestamp")
                    event_type = data.get("event_type")
                    payload = data.get("payload", {})
                    prev_hash = data.get("previous_hash")
                    entry_hash = data.get("entry_hash")

                    if prev_hash != expected_prev:
                        return (
                            False,
                            f"Quebra de encadeamento na linha {idx}: previous_hash esperado '{expected_prev}', obtido '{prev_hash}'",
                            count,
                        )

                    computed = compute_event_hash(
                        event_id=event_id,
                        timestamp=timestamp,
                        event_type=event_type,
                        payload=payload,
                        previous_hash=prev_hash,
                    )
                    if computed != entry_hash:
                        return (
                            False,
                            f"Adulteração detectada na linha {idx}: hash calculado '{computed}' difere de '{entry_hash}'",
                            count,
                        )

                    expected_prev = entry_hash

            return True, None, count
