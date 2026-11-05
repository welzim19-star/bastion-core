"""Telemetry Package for Bastion Audit Enterprise."""
from .killcam_logger import setup_telemetry, get_logger, record_killcam, track_action

__all__ = ["setup_telemetry", "get_logger", "record_killcam", "track_action"]
