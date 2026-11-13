"""
Bastion Audit v2.0 Enterprise - Main Entrypoint & CLI Interface
"""
from __future__ import annotations

import argparse
import os
import sys

# Garante importação correta dos pacotes internos
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

from config.settings import load_config
from core.engine import BastionCoreEngine
from service.windows_service import install_windows_service, uninstall_windows_service
from telemetry.killcam_logger import setup_telemetry, get_logger


def print_banner():
    banner = r"""
  ____            _   _               _             _ _ _   
 |  _ \          | | (_)             / \           | (_) |  
 | |_) | __ _ ___| |_ _  ___  _ __  / _ \ _   _  __| |_| |_ 
 |  _ < / _` / __| __| |/ _ \| '_ \/ ___ \ | | |/ _` | | __|
 | |_) | (_| \__ \ |_| | (_) | | | / ___ \ |_| | (_| | | |_ 
 |____/ \__,_|___/\__|_|\___/|_| |_/_/   \_\__,_|\__,_|_|\__|
   [ BASTION AUDIT v2.0 ENTERPRISE · BANK-GRADE EDITION ]
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Bastion Audit v2.0 Enterprise - Sensor de Inventário L2, Resiliência e Auditoria Imutável"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Caminho personalizado para o arquivo de configuração JSON",
    )
    parser.add_argument(
        "--scan-once",
        action="store_true",
        help="Executa uma única varredura de radar e finaliza",
    )
    parser.add_argument(
        "--verify-audit",
        action="store_true",
        help="Verifica a integridade criptográfica SHA-256 do arquivo de auditoria",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Exibe o resumo consolidado de dispositivos no inventário",
    )
    parser.add_argument(
        "--install-service",
        action="store_true",
        help="Registra o executável como Serviço Nativo do Windows",
    )
    parser.add_argument(
        "--uninstall-service",
        action="store_true",
        help="Remove o Serviço Nativo do Windows",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        default=True,
        help="Inicia o servidor web da Dashboard Interativa (Padrão: True)",
    )
    parser.add_argument(
        "--no-web",
        dest="web",
        action="store_false",
        help="Desativa o servidor web da Dashboard",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=int(os.environ.get("PORT", "5055")),
        help="Porta HTTP para o servidor web (Padrão: 5055 ou $PORT)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host de escuta HTTP (Padrão: 0.0.0.0)",
    )

    args = parser.parse_args()

    # 1. Carrega Configurações
    config = load_config(args.config)

    # 2. Inicializa Telemetria & Logger
    setup_telemetry(config.storage.system_log_path)
    log = get_logger()

    # 3. Tratamento de Comandos de Serviço
    if args.install_service:
        exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        install_windows_service(exe_path)
        return

    if args.uninstall_service:
        uninstall_windows_service()
        return

    print_banner()

    # 4. Instancia o Core Engine
    engine = BastionCoreEngine(config)

    # 5. Modos de Operação
    if args.verify_audit:
        print("[*] Iniciando verificação de integridade da trilha de auditoria...")
        is_valid = engine.verify_ledger_integrity()
        if is_valid:
            print("[+] SUCESSO: Trilha de auditoria 100% íntegra. Nenhuma adulteração detectada.")
            sys.exit(0)
        else:
            print("[-] FALHA CRÍTICA: Trilha de auditoria violada ou corrompida!")
            sys.exit(1)

    if args.summary:
        summary = engine.storage.get_audit_summary()
        print("\n========================================================")
        print("          📊 RESUMO DE INVENTÁRIO BASTION ENTERPRISE     ")
        print("========================================================")
        print(f" Total de Dispositivos:   {summary['total_devices']}")
        print(f" Dispositivos Autorizados:{summary['authorized_devices']}")
        print(f" Desconhecidos/Pendentes: {summary['unknown_devices']}")
        print("--------------------------------------------------------")
        print(" Ativos Recentes (Últimos 7 dias):")
        for dev in summary["recent_new_devices"]:
            print(f"  • {dev['mac']} ({dev['vendor']}) - IP: {dev['ip']} - Status: {dev['status']}")
        print("========================================================\n")
        return

    if args.scan_once:
        print("[*] Executando varredura única de radar...")
        count = engine.run_single_scan()
        print(f"[+] Varredura concluída. Dispositivos processados: {count}")
        return

    # Inicia Servidor Web se habilitado
    if args.web:
        from web.server import start_web_server
        import threading
        web_server = start_web_server(engine, host=args.host, port=args.port)
        web_thread = threading.Thread(target=web_server.serve_forever, name="BastionWebServerThread", daemon=True)
        web_thread.start()
        iface = engine.network_probe.detect_active_interface()
        print(f"[+] 🌐 DASHBOARD WEB ONLINE:")
        print(f"    👉 Acesso Local (PC):   http://localhost:{args.port}")
        print(f"    👉 Acesso na Rede LAN:  http://{iface.ip_address}:{args.port}\n")

    # Modo Contínuo Daemon (Padrão)
    print(f"[*] Iniciando Bastion Audit Daemon (Alvo: {config.agent.target_ip})...")
    engine.run()


if __name__ == "__main__":
    main()
