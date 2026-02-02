"""
Enhanced plugin system for VIPSQLi
"""

from .base import (
    PluginBase,
    PluginStatus,
    PluginPriority,
    PluginMetadata,
    DetectionResult
)
from .manager import PluginManager, PluginEvent

__all__ = [
    'PluginBase',
    'PluginStatus',
    'PluginPriority',
    'PluginMetadata',
    'DetectionResult',
    'PluginManager',
    'PluginEvent'
]

__version__ = '2.0.0'