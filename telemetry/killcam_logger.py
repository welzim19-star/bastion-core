"""
Bastion Audit v2.0 Enterprise - Killcam & Telemetry Logger
Observabilidade Agressiva: Telemetria com rastreamento de último comando, arquivo e traceback exato.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import traceback
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Generator, Optional

_state_lock = threading.Lock()
_LAST_ACTION: Dict[str, Any] = {
    "file": None,
    "line": None,
    "action": "system_boot",
    "target": None,
    "timestamp": None,
}


def update_last_action(action: str, target: Optional[str] = None, file_name: Optional[str] = None, line_no: Optional[int] = None):
    with _state_lock:
        _LAST_ACTION["action"] = action
        _LAST_ACTION["target"] = target
        _LAST_ACTION["file"] = file_name
        _LAST_ACTION["line"] = line_no
        _LAST_ACTION["timestamp"] = datetime.now().isoformat()


@contextmanager
def track_action(action: str, target: Optional[str] = None) -> Generator[None, None, None]:
    """Context manager para rastrear comandos e probes executados em tempo real."""
    frame = sys._getframe(2)
    file_name = frame.f_code.co_filename
    line_no = frame.f_lineno
    update_last_action(action=action, target=target, file_name=file_name, line_no=line_no)
    try:
        yield
    except Exception as e:
        record_killcam(e, custom_msg=f"Falha durante ação: [{action}] com alvo: [{target}]")
        raise


def record_killcam(exc: BaseException, custom_msg: str = ""):
    """Registra a killcam com contexto cirúrgico de telemetria."""
    log = get_logger()
    with _state_lock:
        last_act = dict(_LAST_ACTION)

    tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
    tb_str = "".join(tb_lines).strip()

    # Identifica o último frame relevante
    last_file = "Desconhecido"
    last_line = 0
    if exc.__traceback__:
        curr = exc.__traceback__
        while curr.tb_next:
            curr = curr.tb_next
        last_file = curr.tb_frame.f_code.co_filename
        last_line = curr.tb_lineno

    killcam_report = (
        f"\n==================== [ 💀 TELEMETRIA KILLCAM - FALHA CRÍTICA ] ====================\n"
        f"TIMESTAMP:        {datetime.now().isoformat()}\n"
        f"EXCEPTION:        {type(exc).__name__}: {str(exc)}\n"
        f"MENSAGEM:         {custom_msg or 'Nenhuma mensagem adicional'}\n"
        f"ÚLTIMA AÇÃO:      {last_act.get('action')} (Alvo: {last_act.get('target')})\n"
        f"ÚLTIMO ARQUIVO:   {last_file}:{last_line}\n"
        f"REGISTRO INTERNO: {last_act.get('file')}:{last_act.get('line')}\n"
        f"------------------------------------------------------------------------------------\n"
        f"TRACEBACK COMPLETO:\n{tb_str}\n"
        f"====================================================================================\n"
    )
    log.error(killcam_report)


def setup_telemetry(log_file_path: str, level: int = logging.INFO) -> logging.Logger:
    """Configura logging rotativo e stream padrão com formatação estruturada."""
    os.makedirs(os.path.dirname(os.path.abspath(log_file_path)), exist_ok=True)

    root_logger = logging.getLogger("BastionEnterprise")
    root_logger.setLevel(level)

    # Evita duplicação de handlers se já configurado
    if not root_logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File Handler Rotativo (10MB, 5 backups)
        file_handler = RotatingFileHandler(
            log_file_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)

        # Stream Handler (Console)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(level)

        root_logger.addHandler(file_handler)
        root_logger.addHandler(stream_handler)

    # Global unhandled exception hook
    def _unhandled_exception_hook(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        record_killcam(exc_value, custom_msg="Exceção não tratada capturada no nível superior do processo.")

    sys.excepthook = _unhandled_exception_hook
    return root_logger


def get_logger(name: str = "BastionEnterprise") -> logging.Logger:
    if name == "BastionEnterprise" or name.startswith("BastionEnterprise."):
        return logging.getLogger(name)
    return logging.getLogger(f"BastionEnterprise.{name}")


def clear_system_log(log_file_path: str) -> bool:
    """Limpa o arquivo de log de telemetria preservando o descritor aberto."""
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "w", encoding="utf-8") as f:
                f.write("")
        log = get_logger("Telemetry")
        log.info("Log de sistema reinicializado pelo operador via Dashboard.")
        return True
    except Exception:
        return False
