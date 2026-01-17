"""
Configuration Management for Obscura

Supports YAML and JSON configuration files for:
- Interface settings
- Attack parameters
- Hardware preferences
- Logging settings
- Safety interlocks
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class ObscuraConfig:
    """Obscura configuration settings"""
    
    interface: str = "wlan0"
    simulate_mode: bool = False
    battery_saver: bool = False
    
    signal_threshold: int = -120
    jam_duration: int = 300
    deauth_duration: int = 120
    
    log_level: str = "INFO"
    log_file: str = "obscura.log"
    max_log_size: int = 5 * 1024 * 1024
    
    rf_safety_required: bool = True
    
    sdr_preferred: Optional[str] = None
    wifi_preferred: Optional[str] = None
    ble_preferred: Optional[str] = None
    
    tui_enabled: bool = False
    tui_refresh_rate: float = 1.0
    
    auto_load_plugins: bool = True
    plugin_dir: str = "attack_plugins"
    
    fixtures_dir: str = "fixtures"
    fallback_mode: bool = False
    
    mitre_mapping_enabled: bool = True
    reporting_enabled: bool = True
    report_format: str = "markdown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ObscuraConfig':
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ConfigManager:
    """
    Manage Obscura configuration files.
    
    Supports:
    - JSON (.json)
    - YAML (.yml, .yaml)
    - Default configuration
    - Config validation
    """
    
    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".config" / "obscura" / "config.yaml",
        Path.home() / ".config" / "obscura" / "config.json",
        Path.home() / ".obscura.yaml",
        Path.home() / ".obscura.json",
        Path("obscura.yaml"),
        Path("obscura.json"),
    ]
    
    def __init__(self):
        self.config = ObscuraConfig()
        self.config_path: Optional[Path] = None
    
    def load(self, config_path: Optional[str] = None) -> ObscuraConfig:
        """
        Load configuration from file.
        
        Args:
            config_path: Path to config file. If None, searches default locations.
            
        Returns:
            ObscuraConfig instance
        """
        if config_path:
            path = Path(config_path)
            if not path.exists():
                raise FileNotFoundError(f"Config file not found: {config_path}")
            self.config_path = path
            self.config = self._load_file(path)
        else:
            for path in self.DEFAULT_CONFIG_PATHS:
                if path.exists():
                    self.config_path = path
                    self.config = self._load_file(path)
                    break
        
        return self.config
    
    def _load_file(self, path: Path) -> ObscuraConfig:
        """Load config from specific file."""
        suffix = path.suffix.lower()
        
        with open(path, 'r') as f:
            if suffix == '.json':
                data = json.load(f)
            elif suffix in ['.yaml', '.yml']:
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
                data = yaml.safe_load(f)
            else:
                raise ValueError(f"Unsupported config format: {suffix}")
        
        return ObscuraConfig.from_dict(data)
    
    def save(self, config_path: Optional[str] = None, format: str = "yaml") -> None:
        """
        Save configuration to file.
        
        Args:
            config_path: Path to save config. If None, uses loaded path or default.
            format: Config format ('json' or 'yaml')
        """
        if config_path:
            path = Path(config_path)
        elif self.config_path:
            path = self.config_path
        else:
            if format == "yaml":
                path = self.DEFAULT_CONFIG_PATHS[0]
            else:
                path = self.DEFAULT_CONFIG_PATHS[1]
        
        path.parent.mkdir(parents=True, exist_ok=True)
        
        data = self.config.to_dict()
        
        with open(path, 'w') as f:
            if format == "json":
                json.dump(data, f, indent=2)
            elif format in ["yaml", "yml"]:
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
                yaml.safe_dump(data, f, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {format}")
        
        self.config_path = path
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
        else:
            raise ValueError(f"Invalid config key: {key}")
    
    def generate_template(self, output_path: str, format: str = "yaml") -> None:
        """
        Generate configuration template file.
        
        Args:
            output_path: Path to save template
            format: Config format ('json' or 'yaml')
        """
        default_config = ObscuraConfig()
        temp_config = self.config
        self.config = default_config
        self.save(output_path, format)
        self.config = temp_config
    
    def validate(self) -> List[str]:
        """
        Validate configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if self.config.jam_duration < 1:
            errors.append("jam_duration must be >= 1")
        
        if self.config.deauth_duration < 1:
            errors.append("deauth_duration must be >= 1")
        
        if self.config.signal_threshold > 0:
            errors.append("signal_threshold must be negative (dBm)")
        
        if self.config.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            errors.append(f"Invalid log_level: {self.config.log_level}")
        
        if self.config.report_format not in ["markdown", "json", "html", "pdf"]:
            errors.append(f"Invalid report_format: {self.config.report_format}")
        
        if self.config.tui_refresh_rate < 0.1:
            errors.append("tui_refresh_rate must be >= 0.1")
        
        return errors
    
    def print_config(self) -> None:
        """Print current configuration."""
        print("Current Configuration:")
        print("=" * 60)
        for key, value in self.config.to_dict().items():
            print(f"  {key}: {value}")
        print("=" * 60)
        if self.config_path:
            print(f"Loaded from: {self.config_path}")
        else:
            print("Using default configuration")


def load_config(config_path: Optional[str] = None) -> ObscuraConfig:
    """
    Convenience function to load configuration.
    
    Args:
        config_path: Path to config file (optional)
        
    Returns:
        ObscuraConfig instance
    """
    manager = ConfigManager()
    return manager.load(config_path)


def save_config(config: ObscuraConfig, config_path: str, format: str = "yaml") -> None:
    """
    Convenience function to save configuration.
    
    Args:
        config: ObscuraConfig instance
        config_path: Path to save config
        format: Config format ('json' or 'yaml')
    """
    manager = ConfigManager()
    manager.config = config
    manager.save(config_path, format)


def generate_config_template(output_path: str, format: str = "yaml") -> None:
    """
    Generate configuration template file.
    
    Args:
        output_path: Path to save template
        format: Config format ('json' or 'yaml')
    """
    manager = ConfigManager()
    manager.generate_template(output_path, format)
    print(f"[+] Configuration template generated: {output_path}")
    print(f"[*] Edit this file and use --config {output_path} to load it")
