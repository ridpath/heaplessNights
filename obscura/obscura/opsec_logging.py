"""
OpSec-Grade Logging for Red Team Operations

Provides operational security features for logging:
- Encrypted log storage (AES-256-GCM)
- Sensitive data redaction (IPs, MACs, credentials)
- Memory-only logging mode
- Auto-cleanup and secure deletion
- Session management with operator tracking
- Evidence chain of custody
- Cryptographic hashing of artifacts

MITRE ATT&CK: T1070.004 (File Deletion), T1027 (Obfuscated Files or Information)
"""

import os
import sys
import json
import hashlib
import secrets
import shutil
import sqlite3
import gzip
import threading
import queue
import platform
import logging
import time
import subprocess
import struct
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict, field
import re

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == 'Windows'
IS_LINUX = PLATFORM == 'Linux'
IS_MACOS = PLATFORM == 'Darwin'
IS_WSL = IS_LINUX and 'microsoft' in platform.uname().release.lower()

def _detect_wsl_distro() -> Optional[str]:
    """Detect WSL distribution name"""
    if not IS_WSL:
        return None
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('NAME='):
                        return line.split('=')[1].strip().strip('"')
    except:
        pass
    return "WSL"

WSL_DISTRO = _detect_wsl_distro() if IS_WSL else None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('opsec_logging')


class PlatformUtils:
    """Cross-platform utility functions"""
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with elevated privileges"""
        try:
            if IS_WINDOWS:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    @staticmethod
    def wsl_to_windows_path(wsl_path: str) -> Optional[str]:
        """Convert WSL path to Windows path"""
        if not IS_WSL:
            return None
        try:
            result = subprocess.run(
                ['wslpath', '-w', wsl_path],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        try:
            wsl_path = Path(wsl_path).resolve()
            if str(wsl_path).startswith('/mnt/'):
                parts = str(wsl_path).split('/')
                drive = parts[2].upper()
                rest = '/'.join(parts[3:])
                win_rest = rest.replace('/', '\\')
                return f"{drive}:\\{win_rest}"
        except:
            pass
        return None
    
    @staticmethod
    def windows_to_wsl_path(win_path: str) -> Optional[str]:
        """Convert Windows path to WSL path"""
        if not IS_WSL:
            return None
        try:
            result = subprocess.run(
                ['wslpath', '-u', win_path],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        try:
            if ':' in win_path:
                drive = win_path[0].lower()
                rest = win_path[2:].replace('\\', '/')
                return f"/mnt/{drive}{rest}"
        except:
            pass
        return None
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get network interfaces (platform-agnostic)"""
        interfaces = []
        
        if PSUTIL_AVAILABLE:
            try:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                
                for iface_name, iface_addrs in addrs.items():
                    iface_info = {
                        'name': iface_name,
                        'addresses': [],
                        'is_up': stats[iface_name].isup if iface_name in stats else False
                    }
                    
                    for addr in iface_addrs:
                        if addr.family == 2:
                            iface_info['addresses'].append({
                                'type': 'ipv4',
                                'address': addr.address,
                                'netmask': addr.netmask
                            })
                        elif addr.family == 23 or addr.family == 30:
                            iface_info['addresses'].append({
                                'type': 'ipv6',
                                'address': addr.address
                            })
                        elif hasattr(addr, 'address') and ':' in str(addr.address):
                            iface_info['addresses'].append({
                                'type': 'mac',
                                'address': addr.address
                            })
                    
                    interfaces.append(iface_info)
            except Exception as e:
                logger.debug(f"psutil interface detection failed: {e}")
        
        if not interfaces:
            try:
                if IS_WINDOWS:
                    result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    interfaces.append({
                        'name': 'detected_via_shell',
                        'raw_output': result.stdout[:500]
                    })
            except:
                pass
        
        return interfaces
    
    @staticmethod
    def get_processes(filter_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get running processes (platform-agnostic)"""
        processes = []
        
        if PSUTIL_AVAILABLE:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                    try:
                        pinfo = proc.info
                        if filter_name and filter_name.lower() not in pinfo['name'].lower():
                            continue
                        processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'username': pinfo.get('username', 'unknown'),
                            'cmdline': ' '.join(pinfo.get('cmdline', []))[:200]
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception as e:
                logger.debug(f"psutil process enumeration failed: {e}")
        
        if not processes:
            try:
                if IS_WINDOWS:
                    result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[:50]
                    processes.append({
                        'source': 'shell',
                        'count': len(lines),
                        'sample': '\n'.join(lines[:10])
                    })
            except:
                pass
        
        return processes
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """Secure file deletion (platform-specific)"""
        path = Path(file_path)
        if not path.exists():
            return False
        
        try:
            if IS_LINUX or IS_MACOS:
                try:
                    result = subprocess.run(
                        ['shred', '-n', str(passes), '-z', '-u', str(path)], 
                        capture_output=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        return True
                except:
                    pass
            
            file_size = path.stat().st_size
            with open(path, 'ba+', buffering=0) as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            path.unlink()
            return True
            
        except Exception as e:
            logger.error(f"Secure delete failed: {e}")
            try:
                path.unlink()
                return True
            except:
                return False
    
    @staticmethod
    def detect_hardware_acceleration() -> Dict[str, bool]:
        """Detect hardware acceleration capabilities"""
        capabilities = {
            'aes_ni': False,
            'avx2': False,
            'sse4': False
        }
        
        try:
            if IS_WINDOWS or IS_LINUX:
                if IS_WINDOWS:
                    result = subprocess.run(
                        ['wmic', 'cpu', 'get', 'caption'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                else:
                    result = subprocess.run(
                        ['cat', '/proc/cpuinfo'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                
                if result.returncode == 0:
                    output_lower = result.stdout.lower()
                    capabilities['aes_ni'] = 'aes' in output_lower
                    capabilities['avx2'] = 'avx2' in output_lower
                    capabilities['sse4'] = 'sse4' in output_lower
        except:
            pass
        
        return capabilities
    
    @staticmethod
    def get_system_entropy() -> int:
        """Get available system entropy (Linux)"""
        if IS_LINUX:
            try:
                with open('/proc/sys/kernel/random/entropy_avail') as f:
                    return int(f.read().strip())
            except:
                pass
        return -1


@dataclass
class OperationSession:
    """Red team operation session metadata"""
    session_id: str
    operator: str
    start_time: float
    end_time: Optional[float] = None
    operation_name: str = "Unnamed Operation"
    target_network: str = "Unknown"
    client: str = "Unknown"
    authorization: str = ""
    classification: str = "CONFIDENTIAL"
    chains_executed: int = 0
    artifacts_collected: List[str] = field(default_factory=list)
    evidence_hash: Optional[str] = None
    notes: str = ""
    platform: str = PLATFORM
    wsl_mode: bool = IS_WSL


@dataclass
class PerformanceMetrics:
    """Performance tracking for logging operations"""
    total_logs: int = 0
    total_evidence: int = 0
    total_sessions: int = 0
    avg_log_time_ms: float = 0.0
    total_bytes_written: int = 0
    total_bytes_compressed: int = 0
    compression_ratio: float = 0.0
    start_time: float = field(default_factory=time.time)
    
    def calculate_throughput(self) -> float:
        """Calculate logs per second"""
        elapsed = time.time() - self.start_time
        return self.total_logs / elapsed if elapsed > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary"""
        return {
            'total_logs': self.total_logs,
            'total_evidence': self.total_evidence,
            'total_sessions': self.total_sessions,
            'avg_log_time_ms': self.avg_log_time_ms,
            'total_bytes_written': self.total_bytes_written,
            'total_bytes_compressed': self.total_bytes_compressed,
            'compression_ratio': self.compression_ratio,
            'throughput_logs_per_sec': self.calculate_throughput(),
            'uptime_seconds': time.time() - self.start_time,
            'platform': PLATFORM,
            'wsl_mode': IS_WSL
        }


@dataclass
class Evidence:
    """Evidence artifact with chain of custody"""
    artifact_id: str
    timestamp: float
    operator: str
    artifact_type: str
    file_path: Optional[str] = None
    data_hash: Optional[str] = None
    description: str = ""
    chain_id: Optional[str] = None
    pcap_reference: Optional[str] = None
    screenshot_reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SensitiveDataRedactor:
    """Redact sensitive information from logs"""
    
    IPV4_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
    MAC_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    CREDENTIAL_PATTERN = re.compile(r'(?:password|passwd|pwd|apikey|api_key|token|secret)[\s:=]+[\S]+', re.IGNORECASE)
    
    def __init__(self, redact_ips: bool = True, redact_macs: bool = True, 
                 redact_domains: bool = False, redact_credentials: bool = True):
        self.redact_ips = redact_ips
        self.redact_macs = redact_macs
        self.redact_domains = redact_domains
        self.redact_credentials = redact_credentials
        self.ip_map = {}
        self.mac_map = {}
        self.domain_map = {}
    
    def redact(self, text: str) -> str:
        """Redact sensitive data from text"""
        if not isinstance(text, str):
            text = str(text)
        
        if self.redact_ips:
            text = self._redact_ipv4(text)
            text = self._redact_ipv6(text)
        
        if self.redact_macs:
            text = self._redact_macs(text)
        
        if self.redact_domains:
            text = self._redact_domains(text)
        
        if self.redact_credentials:
            text = self._redact_credentials(text)
        
        return text
    
    def _redact_ipv4(self, text: str) -> str:
        """Redact IPv4 addresses with consistent placeholders"""
        def replace_ip(match):
            ip = match.group(0)
            if ip == "127.0.0.1" or ip.startswith("0."):
                return ip
            if ip not in self.ip_map:
                self.ip_map[ip] = f"IP_{len(self.ip_map) + 1}"
            return f"[{self.ip_map[ip]}]"
        
        return self.IPV4_PATTERN.sub(replace_ip, text)
    
    def _redact_ipv6(self, text: str) -> str:
        """Redact IPv6 addresses"""
        def replace_ip(match):
            ip = match.group(0)
            if ip not in self.ip_map:
                self.ip_map[ip] = f"IPV6_{len(self.ip_map) + 1}"
            return f"[{self.ip_map[ip]}]"
        
        return self.IPV6_PATTERN.sub(replace_ip, text)
    
    def _redact_macs(self, text: str) -> str:
        """Redact MAC addresses"""
        def replace_mac(match):
            mac = match.group(0)
            if mac not in self.mac_map:
                self.mac_map[mac] = f"MAC_{len(self.mac_map) + 1}"
            return f"[{self.mac_map[mac]}]"
        
        return self.MAC_PATTERN.sub(replace_mac, text)
    
    def _redact_domains(self, text: str) -> str:
        """Redact domain names"""
        def replace_domain(match):
            domain = match.group(0)
            if domain not in self.domain_map:
                self.domain_map[domain] = f"DOMAIN_{len(self.domain_map) + 1}"
            return f"[{self.domain_map[domain]}]"
        
        return self.DOMAIN_PATTERN.sub(replace_domain, text)
    
    def _redact_credentials(self, text: str) -> str:
        """Redact credentials"""
        return self.CREDENTIAL_PATTERN.sub('[REDACTED_CREDENTIAL]', text)
    
    def get_redaction_map(self) -> Dict[str, Any]:
        """Get mapping of redacted values (for secure storage)"""
        return {
            'ips': dict(self.ip_map),
            'macs': dict(self.mac_map),
            'domains': dict(self.domain_map)
        }


class EncryptedLogger:
    """Encrypt logs using AES-256-GCM with keyring support"""
    
    KEYRING_SERVICE = "obscura_opsec"
    
    def __init__(self, key: Optional[bytes] = None, passphrase: Optional[str] = None,
                 keyring_username: Optional[str] = None, auto_save_keyring: bool = False):
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required. Install with: pip install cryptography")
        
        self.keyring_username = keyring_username
        self.auto_save_keyring = auto_save_keyring
        
        if key:
            self.key = key
        elif keyring_username and KEYRING_AVAILABLE:
            self.key = self._load_key_from_keyring(keyring_username)
            if not self.key:
                logger.warning(f"No key found in keyring for {keyring_username}, generating new key")
                self.key = AESGCM.generate_key(bit_length=256)
                if auto_save_keyring:
                    self._save_key_to_keyring(keyring_username, self.key)
        elif passphrase:
            self.key = self._derive_key(passphrase)
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            logger.info("Generated new encryption key (not saved)")
        
        self.cipher = AESGCM(self.key)
    
    def _load_key_from_keyring(self, username: str) -> Optional[bytes]:
        """Load encryption key from system keyring"""
        if not KEYRING_AVAILABLE:
            logger.warning("keyring library not available")
            return None
        
        try:
            key_b64 = keyring.get_password(self.KEYRING_SERVICE, username)
            if key_b64:
                import base64
                return base64.b64decode(key_b64)
        except Exception as e:
            logger.error(f"Failed to load key from keyring: {e}")
        return None
    
    def _save_key_to_keyring(self, username: str, key: bytes) -> bool:
        """Save encryption key to system keyring"""
        if not KEYRING_AVAILABLE:
            logger.warning("keyring library not available, cannot save key")
            return False
        
        try:
            import base64
            key_b64 = base64.b64encode(key).decode('ascii')
            keyring.set_password(self.KEYRING_SERVICE, username, key_b64)
            logger.info(f"Encryption key saved to keyring for {username}")
            return True
        except Exception as e:
            logger.error(f"Failed to save key to keyring: {e}")
            return False
    
    def _derive_key(self, passphrase: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from passphrase"""
        if salt is None:
            salt = b'obscura_salt_v1'
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(passphrase.encode())
    
    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        nonce = secrets.token_bytes(12)
        ciphertext = self.cipher.encrypt(nonce, data, None)
        
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        return self.cipher.decrypt(nonce, ciphertext, None)
    
    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encrypt file"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt file"""
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.decrypt(encrypted)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)


class OpSecLogger:
    """
    Operational Security Logger for Red Team Operations
    
    Features:
    - Encrypted log storage
    - Sensitive data redaction
    - Memory-only mode
    - Session management
    - Evidence chain of custody
    - Secure auto-cleanup
    """
    
    def __init__(self, 
                 log_dir: str = 'opsec_logs',
                 encrypt: bool = True,
                 redact: bool = True,
                 memory_only: bool = False,
                 passphrase: Optional[str] = None,
                 operator: str = "unknown",
                 auto_cleanup: bool = False,
                 cleanup_age_hours: int = 24,
                 async_logging: bool = False,
                 compress_logs: bool = True,
                 rotate_size_mb: int = 10,
                 ctf_mode: bool = False,
                 keyring_username: Optional[str] = None,
                 auto_backup: bool = False,
                 backup_dir: Optional[str] = None,
                 enable_metrics: bool = True):
        
        logger.info(f"Initializing OpSecLogger on {PLATFORM} (WSL: {IS_WSL})")
        
        self.log_dir = Path(log_dir)
        self.encrypt = encrypt
        self.redact = redact
        self.memory_only = memory_only
        self.operator = operator
        self.auto_cleanup = auto_cleanup
        self.cleanup_age_hours = cleanup_age_hours
        self.async_logging = async_logging
        self.compress_logs = compress_logs
        self.rotate_size_mb = rotate_size_mb
        self.ctf_mode = ctf_mode
        self.auto_backup = auto_backup
        self.backup_dir = Path(backup_dir) if backup_dir else self.log_dir / 'backups'
        self.enable_metrics = enable_metrics
        
        if not memory_only:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                if auto_backup:
                    self.backup_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Log directory created: {self.log_dir}")
            except Exception as e:
                logger.error(f"Failed to create log directory: {e}")
                raise
        
        self.encryptor = None
        if encrypt and CRYPTO_AVAILABLE:
            try:
                self.encryptor = EncryptedLogger(
                    passphrase=passphrase,
                    keyring_username=keyring_username,
                    auto_save_keyring=True if keyring_username else False
                )
                logger.info("Encryption enabled with AES-256-GCM")
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")
                if keyring_username:
                    logger.warning("Falling back to passphrase-based encryption")
                    self.encryptor = EncryptedLogger(passphrase=passphrase)
        elif encrypt:
            logger.warning("Encryption requested but cryptography library not available")
        
        self.redactor = SensitiveDataRedactor() if redact else None
        
        self.memory_logs: List[Dict[str, Any]] = []
        self.current_session: Optional[OperationSession] = None
        self.evidence_chain: List[Evidence] = []
        
        self.db_path = self.log_dir / 'operations.db' if not memory_only else None
        if self.db_path:
            try:
                self._init_database()
                logger.info(f"Database initialized: {self.db_path}")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise
        
        self.log_queue: Optional[queue.Queue] = None
        self.log_thread: Optional[threading.Thread] = None
        if async_logging:
            try:
                self._init_async_logging()
                logger.info("Async logging enabled")
            except Exception as e:
                logger.error(f"Failed to initialize async logging: {e}")
        
        self.ctf_score = 0
        self.ctf_flags: List[Dict[str, Any]] = []
        
        self.metrics = PerformanceMetrics() if enable_metrics else None
        
        self._log_lock = threading.Lock()
        
        logger.info(f"OpSecLogger initialized successfully (operator: {operator})")
    
    def _init_database(self) -> None:
        """Initialize SQLite database for session and evidence tracking"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                operator TEXT,
                start_time REAL,
                end_time REAL,
                operation_name TEXT,
                target_network TEXT,
                client TEXT,
                authorization TEXT,
                classification TEXT,
                chains_executed INTEGER,
                evidence_hash TEXT,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                artifact_id TEXT PRIMARY KEY,
                timestamp REAL,
                operator TEXT,
                artifact_type TEXT,
                file_path TEXT,
                data_hash TEXT,
                description TEXT,
                chain_id TEXT,
                pcap_reference TEXT,
                screenshot_reference TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp REAL,
                chain_id TEXT,
                attack_name TEXT,
                success INTEGER,
                execution_time REAL,
                target_info TEXT,
                log_data TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def start_session(self, operation_name: str, target_network: str = "Unknown",
                     client: str = "Unknown", authorization: str = "") -> str:
        """Start a new operation session"""
        session_id = f"OP_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        
        self.current_session = OperationSession(
            session_id=session_id,
            operator=self.operator,
            start_time=datetime.now().timestamp(),
            operation_name=operation_name,
            target_network=target_network,
            client=client,
            authorization=authorization
        )
        
        if not self.memory_only and self.db_path:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id, self.operator, self.current_session.start_time, None,
                operation_name, target_network, client, authorization,
                self.current_session.classification, 0, None, ""
            ))
            conn.commit()
            conn.close()
        
        return session_id
    
    def end_session(self, notes: str = "") -> None:
        """End current operation session"""
        if not self.current_session:
            return
        
        self.current_session.end_time = datetime.now().timestamp()
        self.current_session.notes = notes
        
        evidence_data = json.dumps([asdict(e) for e in self.evidence_chain])
        self.current_session.evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()
        
        if not self.memory_only and self.db_path:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET end_time = ?, chains_executed = ?, evidence_hash = ?, notes = ?
                WHERE session_id = ?
            ''', (
                self.current_session.end_time,
                self.current_session.chains_executed,
                self.current_session.evidence_hash,
                notes,
                self.current_session.session_id
            ))
            conn.commit()
            conn.close()
    
    def log_attack(self, chain_id: str, attack_name: str, success: bool,
                   execution_time: float, target_info: Dict[str, Any],
                   log_data: Dict[str, Any]) -> None:
        """Log an attack execution"""
        start_log_time = time.time()
        timestamp = datetime.now().timestamp()
        
        try:
            if self.redactor:
                log_data = json.loads(self.redactor.redact(json.dumps(log_data)))
                target_info = json.loads(self.redactor.redact(json.dumps(target_info)))
            
            log_entry = {
                'timestamp': timestamp,
                'session_id': self.current_session.session_id if self.current_session else None,
                'chain_id': chain_id,
                'attack_name': attack_name,
                'success': success,
                'execution_time': execution_time,
                'target_info': target_info,
                'log_data': log_data
            }
            
            if self.memory_only:
                self.memory_logs.append(log_entry)
            else:
                if self.async_logging and self.log_queue:
                    self.log_queue.put(log_entry)
                else:
                    if self.db_path:
                        conn = sqlite3.connect(str(self.db_path))
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO attack_logs (session_id, timestamp, chain_id, attack_name, success, execution_time, target_info, log_data)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            log_entry['session_id'],
                            timestamp,
                            chain_id,
                            attack_name,
                            1 if success else 0,
                            execution_time,
                            json.dumps(target_info),
                            json.dumps(log_data)
                        ))
                        conn.commit()
                        conn.close()
                
                if self.current_session:
                    self.current_session.chains_executed += 1
            
            if self.metrics:
                log_time_ms = (time.time() - start_log_time) * 1000
                self.metrics.total_logs += 1
                if self.metrics.total_logs == 1:
                    self.metrics.avg_log_time_ms = log_time_ms
                else:
                    self.metrics.avg_log_time_ms = (
                        (self.metrics.avg_log_time_ms * (self.metrics.total_logs - 1) + log_time_ms) 
                        / self.metrics.total_logs
                    )
                
                log_size = len(json.dumps(log_entry))
                self.metrics.total_bytes_written += log_size
            
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
            raise
    
    def add_evidence(self, artifact_type: str, file_path: Optional[str] = None,
                     description: str = "", chain_id: Optional[str] = None,
                     pcap_reference: Optional[str] = None,
                     screenshot_reference: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """Add evidence artifact with chain of custody"""
        artifact_id = f"ARTIFACT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        
        data_hash = None
        if file_path and os.path.exists(file_path):
            data_hash = self._hash_file(file_path)
        
        evidence = Evidence(
            artifact_id=artifact_id,
            timestamp=datetime.now().timestamp(),
            operator=self.operator,
            artifact_type=artifact_type,
            file_path=file_path,
            data_hash=data_hash,
            description=description,
            chain_id=chain_id,
            pcap_reference=pcap_reference,
            screenshot_reference=screenshot_reference,
            metadata=metadata or {}
        )
        
        self.evidence_chain.append(evidence)
        
        if not self.memory_only and self.db_path:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                artifact_id,
                evidence.timestamp,
                self.operator,
                artifact_type,
                file_path,
                data_hash,
                description,
                chain_id,
                pcap_reference,
                screenshot_reference,
                json.dumps(metadata or {})
            ))
            conn.commit()
            conn.close()
        
        if self.current_session:
            self.current_session.artifacts_collected.append(artifact_id)
        
        return artifact_id
    
    def _hash_file(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def export_session(self, session_id: str, output_file: str,
                      include_evidence: bool = True) -> None:
        """Export session data to encrypted file"""
        session_data = {
            'session': None,
            'attacks': [],
            'evidence': []
        }
        
        if self.db_path:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            if row:
                session_data['session'] = {
                    'session_id': row[0],
                    'operator': row[1],
                    'start_time': row[2],
                    'end_time': row[3],
                    'operation_name': row[4],
                    'target_network': row[5],
                    'client': row[6],
                    'authorization': row[7],
                    'classification': row[8],
                    'chains_executed': row[9],
                    'evidence_hash': row[10],
                    'notes': row[11]
                }
            
            cursor.execute('SELECT * FROM attack_logs WHERE session_id = ?', (session_id,))
            for row in cursor.fetchall():
                session_data['attacks'].append({
                    'log_id': row[0],
                    'timestamp': row[2],
                    'chain_id': row[3],
                    'attack_name': row[4],
                    'success': bool(row[5]),
                    'execution_time': row[6],
                    'target_info': json.loads(row[7]),
                    'log_data': json.loads(row[8])
                })
            
            if include_evidence:
                cursor.execute('SELECT * FROM evidence WHERE artifact_id IN (SELECT artifact_id FROM evidence)')
                for row in cursor.fetchall():
                    session_data['evidence'].append({
                        'artifact_id': row[0],
                        'timestamp': row[1],
                        'operator': row[2],
                        'artifact_type': row[3],
                        'file_path': row[4],
                        'data_hash': row[5],
                        'description': row[6],
                        'chain_id': row[7],
                        'pcap_reference': row[8],
                        'screenshot_reference': row[9],
                        'metadata': json.loads(row[10])
                    })
            
            conn.close()
        
        json_data = json.dumps(session_data, indent=2)
        
        if self.encrypt and self.encryptor:
            encrypted = self.encryptor.encrypt(json_data)
            with open(output_file, 'wb') as f:
                f.write(encrypted)
        else:
            with open(output_file, 'w') as f:
                f.write(json_data)
    
    def secure_cleanup(self, age_hours: Optional[int] = None) -> int:
        """Securely delete old logs"""
        if self.memory_only:
            count = len(self.memory_logs)
            self.memory_logs.clear()
            return count
        
        age_hours = age_hours or self.cleanup_age_hours
        cutoff_time = datetime.now().timestamp() - (age_hours * 3600)
        
        deleted_count = 0
        
        for log_file in self.log_dir.glob('*.json'):
            if log_file.stat().st_mtime < cutoff_time:
                self._secure_delete(log_file)
                deleted_count += 1
        
        for log_file in self.log_dir.glob('*.enc'):
            if log_file.stat().st_mtime < cutoff_time:
                self._secure_delete(log_file)
                deleted_count += 1
        
        return deleted_count
    
    def _secure_delete(self, file_path: Path) -> None:
        """Securely delete file using platform-specific methods"""
        if not file_path.exists():
            return
        
        try:
            if PlatformUtils.secure_delete(str(file_path), passes=3):
                logger.debug(f"Securely deleted: {file_path}")
            else:
                logger.warning(f"Secure delete may have failed for: {file_path}")
        except Exception as e:
            logger.warning(f"Secure delete failed for {file_path}: {e}")
            try:
                file_path.unlink()
            except:
                pass
    
    def get_memory_logs(self) -> List[Dict[str, Any]]:
        """Get logs from memory (for memory-only mode)"""
        return self.memory_logs
    
    def log_network_interfaces(self, chain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Log current network interfaces"""
        interfaces = PlatformUtils.get_network_interfaces()
        
        if interfaces:
            self.log_attack(
                chain_id=chain_id or f"network_enum_{secrets.token_hex(4)}",
                attack_name="network_interface_enumeration",
                success=True,
                execution_time=0.0,
                target_info={'platform': PLATFORM, 'is_wsl': IS_WSL},
                log_data={'interfaces': interfaces, 'count': len(interfaces)}
            )
        
        return interfaces
    
    def log_processes(self, filter_name: Optional[str] = None, chain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Log running processes"""
        processes = PlatformUtils.get_processes(filter_name=filter_name)
        
        if processes:
            self.log_attack(
                chain_id=chain_id or f"process_enum_{secrets.token_hex(4)}",
                attack_name="process_enumeration",
                success=True,
                execution_time=0.0,
                target_info={'platform': PLATFORM, 'filter': filter_name or 'all'},
                log_data={'processes': processes[:100], 'total_count': len(processes)}
            )
        
        return processes
    
    def convert_path(self, path: str, to_windows: bool = False) -> Optional[str]:
        """Convert path between WSL and Windows"""
        if not IS_WSL:
            logger.warning("Path conversion only available in WSL")
            return None
        
        if to_windows:
            return PlatformUtils.wsl_to_windows_path(path)
        else:
            return PlatformUtils.windows_to_wsl_path(path)
    
    def export_memory_logs(self, output_file: str) -> None:
        """Export memory logs to file"""
        json_data = json.dumps(self.memory_logs, indent=2)
        
        if self.encrypt and self.encryptor:
            encrypted = self.encryptor.encrypt(json_data)
            with open(output_file, 'wb') as f:
                f.write(encrypted)
        else:
            with open(output_file, 'w') as f:
                f.write(json_data)
    
    def _init_async_logging(self) -> None:
        """Initialize async logging with background thread"""
        self.log_queue = queue.Queue(maxsize=10000)
        self.log_thread = threading.Thread(target=self._async_log_worker, daemon=True)
        self.log_thread.start()
    
    def _async_log_worker(self) -> None:
        """Background worker for async logging"""
        while True:
            try:
                log_item = self.log_queue.get(timeout=1)
                if log_item is None:
                    break
                
                self._write_log_sync(log_item)
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                pass
    
    def _write_log_sync(self, log_entry: Dict[str, Any]) -> None:
        """Synchronously write log entry to database"""
        if not self.db_path or self.memory_only:
            return
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_logs (session_id, timestamp, chain_id, attack_name, success, execution_time, target_info, log_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry['session_id'],
            log_entry['timestamp'],
            log_entry['chain_id'],
            log_entry['attack_name'],
            1 if log_entry['success'] else 0,
            log_entry['execution_time'],
            json.dumps(log_entry['target_info']),
            json.dumps(log_entry['log_data'])
        ))
        conn.commit()
        conn.close()
    
    def shutdown_async_logging(self) -> None:
        """Shutdown async logging gracefully"""
        if self.log_queue and self.log_thread:
            self.log_queue.put(None)
            self.log_thread.join(timeout=5)
    
    def compress_log_file(self, log_file: Path) -> Path:
        """Compress log file using gzip"""
        compressed_file = log_file.with_suffix(log_file.suffix + '.gz')
        
        with open(log_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=9) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        log_file.unlink()
        return compressed_file
    
    def rotate_logs(self) -> int:
        """Rotate logs based on size threshold"""
        if self.memory_only:
            return 0
        
        rotated_count = 0
        max_size_bytes = self.rotate_size_mb * 1024 * 1024
        
        for log_file in self.log_dir.glob('*.json'):
            if log_file.stat().st_size > max_size_bytes:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                rotated_file = log_file.with_name(f"{log_file.stem}_{timestamp}.json")
                log_file.rename(rotated_file)
                
                if self.compress_logs:
                    self.compress_log_file(rotated_file)
                
                rotated_count += 1
        
        if self.db_path and self.db_path.exists():
            db_size_mb = self.db_path.stat().st_size / (1024 * 1024)
            if db_size_mb > self.rotate_size_mb:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                rotated_db = self.db_path.with_name(f"operations_{timestamp}.db")
                shutil.copy(self.db_path, rotated_db)
                
                if self.compress_logs:
                    self.compress_log_file(rotated_db)
                
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                cursor.execute('DELETE FROM attack_logs WHERE timestamp < ?', 
                             (datetime.now().timestamp() - (self.cleanup_age_hours * 3600),))
                conn.commit()
                conn.close()
                
                rotated_count += 1
        
        return rotated_count
    
    def capture_flag(self, flag_name: str, flag_value: str, points: int = 100,
                    chain_id: Optional[str] = None) -> Dict[str, Any]:
        """Capture CTF flag and track score"""
        flag = {
            'flag_name': flag_name,
            'flag_value': flag_value,
            'points': points,
            'timestamp': datetime.now().timestamp(),
            'operator': self.operator,
            'chain_id': chain_id
        }
        
        self.ctf_flags.append(flag)
        self.ctf_score += points
        
        if not self.memory_only:
            flag_file = self.log_dir / f'flag_{flag_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            with open(flag_file, 'w') as f:
                json.dump(flag, f, indent=2)
        
        return flag
    
    def get_ctf_scoreboard(self) -> Dict[str, Any]:
        """Get CTF scoreboard summary"""
        return {
            'operator': self.operator,
            'total_score': self.ctf_score,
            'flags_captured': len(self.ctf_flags),
            'flags': self.ctf_flags,
            'session_id': self.current_session.session_id if self.current_session else None
        }
    
    def export_ctf_report(self, output_file: str) -> None:
        """Export CTF-style simplified report"""
        report = {
            'competition': 'Obscura Red Team CTF',
            'operator': self.operator,
            'timestamp': datetime.now().isoformat(),
            'score': self.ctf_score,
            'flags': self.ctf_flags,
            'session': asdict(self.current_session) if self.current_session else None
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def link_artifact_to_chain(self, artifact_id: str, related_artifact_ids: List[str],
                              relationship: str = "related") -> None:
        """Link artifacts together for correlation analysis"""
        if self.memory_only:
            return
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifact_links (
                link_id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT,
                related_artifact_id TEXT,
                relationship TEXT,
                timestamp REAL,
                FOREIGN KEY (artifact_id) REFERENCES evidence(artifact_id)
            )
        ''')
        
        for related_id in related_artifact_ids:
            cursor.execute('''
                INSERT INTO artifact_links (artifact_id, related_artifact_id, relationship, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (artifact_id, related_id, relationship, datetime.now().timestamp()))
        
        conn.commit()
        conn.close()
    
    def get_artifact_chain(self, artifact_id: str) -> List[Dict[str, Any]]:
        """Get linked artifact chain for correlation"""
        if self.memory_only or not self.db_path:
            return []
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT e.*, al.relationship
            FROM evidence e
            JOIN artifact_links al ON e.artifact_id = al.related_artifact_id
            WHERE al.artifact_id = ?
            ORDER BY e.timestamp
        ''', (artifact_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'artifact_id': row[0],
                'timestamp': row[1],
                'operator': row[2],
                'artifact_type': row[3],
                'file_path': row[4],
                'data_hash': row[5],
                'description': row[6],
                'chain_id': row[7],
                'relationship': row[11]
            })
        
        conn.close()
        return results
    
    def create_backup(self, backup_name: Optional[str] = None) -> Path:
        """Create full backup of all logs and database"""
        if self.memory_only:
            raise ValueError("Cannot backup memory-only logger")
        
        if not backup_name:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Creating backup: {backup_path}")
        
        files_backed_up = 0
        total_size = 0
        
        for file_path in self.log_dir.glob('*'):
            if file_path.is_file() and file_path != self.db_path:
                dest = backup_path / file_path.name
                shutil.copy2(file_path, dest)
                files_backed_up += 1
                total_size += file_path.stat().st_size
        
        if self.db_path and self.db_path.exists():
            shutil.copy2(self.db_path, backup_path / self.db_path.name)
            files_backed_up += 1
            total_size += self.db_path.stat().st_size
        
        backup_manifest = {
            'timestamp': datetime.now().isoformat(),
            'operator': self.operator,
            'files_backed_up': files_backed_up,
            'total_size_bytes': total_size,
            'platform': PLATFORM,
            'wsl_mode': IS_WSL
        }
        
        with open(backup_path / 'manifest.json', 'w') as f:
            json.dump(backup_manifest, f, indent=2)
        
        logger.info(f"Backup created: {files_backed_up} files, {total_size / 1024 / 1024:.2f} MB")
        
        return backup_path
    
    def restore_backup(self, backup_path: Path) -> bool:
        """Restore from backup"""
        if self.memory_only:
            raise ValueError("Cannot restore to memory-only logger")
        
        backup_path = Path(backup_path)
        if not backup_path.exists():
            logger.error(f"Backup path not found: {backup_path}")
            return False
        
        manifest_path = backup_path / 'manifest.json'
        if not manifest_path.exists():
            logger.error("Backup manifest not found")
            return False
        
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            logger.info(f"Restoring backup from {manifest['timestamp']}")
            
            files_restored = 0
            for file_path in backup_path.glob('*'):
                if file_path.name == 'manifest.json':
                    continue
                
                dest = self.log_dir / file_path.name
                shutil.copy2(file_path, dest)
                files_restored += 1
            
            logger.info(f"Restored {files_restored} files from backup")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        if not self.metrics:
            return {}
        
        return self.metrics.to_dict()
    
    def export_metrics(self, output_file: str) -> None:
        """Export metrics to JSON file"""
        if not self.metrics:
            logger.warning("Metrics not enabled")
            return
        
        metrics_data = self.get_metrics()
        
        with open(output_file, 'w') as f:
            json.dump(metrics_data, f, indent=2)
        
        logger.info(f"Metrics exported to {output_file}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for diagnostics"""
        info = {
            'platform': PLATFORM,
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'is_wsl': IS_WSL,
            'wsl_distro': WSL_DISTRO,
            'is_windows': IS_WINDOWS,
            'is_linux': IS_LINUX,
            'is_macos': IS_MACOS,
            'is_admin': PlatformUtils.is_admin(),
            'crypto_available': CRYPTO_AVAILABLE,
            'keyring_available': KEYRING_AVAILABLE,
            'psutil_available': PSUTIL_AVAILABLE,
            'log_dir': str(self.log_dir),
            'operator': self.operator,
            'encryption_enabled': self.encrypt,
            'redaction_enabled': self.redact,
            'async_logging': self.async_logging,
            'ctf_mode': self.ctf_mode,
            'hardware_acceleration': PlatformUtils.detect_hardware_acceleration()
        }
        
        if IS_LINUX:
            entropy = PlatformUtils.get_system_entropy()
            if entropy > 0:
                info['system_entropy'] = entropy
        
        if PSUTIL_AVAILABLE:
            try:
                info['network_interfaces_count'] = len(PlatformUtils.get_network_interfaces())
                info['cpu_percent'] = psutil.cpu_percent(interval=0.1)
                info['memory_percent'] = psutil.virtual_memory().percent
                info['disk_usage_percent'] = psutil.disk_usage(str(self.log_dir)).percent if not self.memory_only else 0
            except:
                pass
        
        return info
    
    def healthcheck(self) -> Dict[str, Any]:
        """Perform system healthcheck"""
        health = {
            'status': 'healthy',
            'checks': {},
            'timestamp': datetime.now().isoformat()
        }
        
        if not self.memory_only:
            health['checks']['log_directory'] = {
                'exists': self.log_dir.exists(),
                'writable': os.access(self.log_dir, os.W_OK) if self.log_dir.exists() else False
            }
            
            if self.db_path:
                health['checks']['database'] = {
                    'exists': self.db_path.exists(),
                    'size_mb': self.db_path.stat().st_size / 1024 / 1024 if self.db_path.exists() else 0
                }
        
        if self.async_logging:
            health['checks']['async_logging'] = {
                'thread_alive': self.log_thread.is_alive() if self.log_thread else False,
                'queue_size': self.log_queue.qsize() if self.log_queue else 0
            }
        
        if self.encryptor:
            health['checks']['encryption'] = {
                'enabled': True,
                'algorithm': 'AES-256-GCM'
            }
        
        if self.metrics:
            health['checks']['metrics'] = self.get_metrics()
        
        if any(not check.get('exists', True) or not check.get('writable', True) 
               for check in health['checks'].values() if isinstance(check, dict)):
            health['status'] = 'degraded'
        
        return health
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        logger.info("Shutting down OpSecLogger")
        
        if self.async_logging:
            self.shutdown_async_logging()
        
        if self.current_session and not self.current_session.end_time:
            self.end_session("Session terminated (context manager exit)")
        
        if self.auto_backup and not self.memory_only:
            try:
                self.create_backup()
            except Exception as e:
                logger.error(f"Failed to create automatic backup: {e}")
        
        logger.info("OpSecLogger shutdown complete")
        
        return False
