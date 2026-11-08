"""
Bastion Audit v2.0 Enterprise - Windows Service Manager Wrapper
Utilitário para registrar e gerenciar o Bastion como Serviço Nativo do Windows (SCM).
"""
from __future__ import annotations

import os
import subprocess
import sys


def install_windows_service(exe_path: str, service_name: str = "BastionAuditService"):
    """Instala o binário como Serviço Nativo do Windows via sc.exe."""
    if os.name != "nt":
        print("[ERRO] Instalação de Serviço do Windows só pode ser executada em sistemas Windows.")
        return False

    display_name = "Bastion Audit Enterprise Service"
    binpath = f'"{exe_path}" --service'
    cmd = [
        "sc",
        "create",
        service_name,
        f"binPath= {binpath}",
        "start= auto",
        f"DisplayName= {display_name}",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"[SUCESSO] Serviço '{service_name}' instalado com sucesso.")
            subprocess.run(["sc", "start", service_name], capture_output=True)
            return True
        else:
            print(f"[ERRO] Falha ao criar serviço Windows: {res.stderr}")
            return False
    except Exception as e:
        print(f"[EXCEÇÃO] Falha ao executar sc.exe: {e}")
        return False


def uninstall_windows_service(service_name: str = "BastionAuditService"):
    """Remove o serviço do Windows."""
    if os.name != "nt":
        return False
    subprocess.run(["sc", "stop", service_name], capture_output=True)
    res = subprocess.run(["sc", "delete", service_name], capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[SUCESSO] Serviço '{service_name}' removido com sucesso.")
        return True
    else:
        print(f"[ERRO] Falha ao remover serviço: {res.stderr}")
        return False
