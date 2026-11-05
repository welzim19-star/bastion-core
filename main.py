"""
Bastion Core CLI - Asynchronous Network Audit & Security Ledger Engine
Zero-PII & Defensive Architecture Runner
"""
import argparse
import sys
import time

from config.settings import BastionConfig
from core.engine import BastionCoreEngine
from telemetry.killcam_logger import get_logger

log = get_logger("BastionCLI")


def main():
    parser = argparse.ArgumentParser(
        description="Bastion-Core: Zero-Trust Network Audit & Immutable Ledger Engine"
    )
    parser.add_argument(
        "--subnet",
        type=str,
        default="auto",
        help="Target subnet to audit (default: 'auto' for active interface discovery)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Maximum concurrent probe workers (default: 20)",
    )
    parser.add_argument(
        "--audit-log",
        type=str,
        default="bastion_audit_trail.jsonl",
        help="Path for SHA-256 chained audit ledger (default: bastion_audit_trail.jsonl)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="bastion_inventory.db",
        help="SQLite WAL inventory database path (default: bastion_inventory.db)",
    )
    parser.add_argument(
        "--single-sweep",
        action="store_true",
        help="Execute single audit pass and print summary report, then exit",
    )
    args = parser.parse_args()

    config = BastionConfig()
    config.agent.base_subnet = args.subnet
    config.agent.max_concurrent_pings = args.workers
    config.storage.audit_log_filename = args.audit_log
    config.storage.db_filename = args.db_path

    log.info("Initializing Bastion-Core Engine...")
    engine = BastionCoreEngine(config)

    try:
        engine.startup()
        if args.single_sweep:
            log.info("Running single audit sweep...")
            devices = engine.probe_and_sync()
            log.info("Audit sweep completed. Discovered %d active endpoint(s).", len(devices))
        else:
            log.info("Starting continuous audit daemon (Press Ctrl+C to terminate)...")
            engine.run()
    except KeyboardInterrupt:
        log.info("Termination signal received. Shutting down cleanly...")
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
