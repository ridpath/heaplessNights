"""
Process Manager for Obscura

Thread-safe process management for RF and attack processes.
Eliminates race conditions from global HACKRF_PROCESS and ACTIVE_PROCESSES variables.
"""

import subprocess
import threading
import logging
from typing import List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("obscura.process_manager")


@dataclass
class ManagedProcess:
    """Represents a managed process with metadata"""
    process: subprocess.Popen
    name: str
    started_at: datetime = field(default_factory=datetime.now)
    attack_type: str = "unknown"


class ProcessManager:
    """
    Thread-safe process manager for Obscura attacks.
    
    Handles:
    - HackRF SDR processes
    - General attack processes (mdk4, etc.)
    - GNU Radio flowgraphs
    - Process cleanup and termination
    """
    
    def __init__(self):
        self._hackrf_process: Optional[ManagedProcess] = None
        self._active_processes: List[ManagedProcess] = []
        self._lock = threading.RLock()
        logger.info("ProcessManager initialized")
    
    def set_hackrf_process(self, process: subprocess.Popen, name: str = "hackrf_transfer", attack_type: str = "rf_jam") -> None:
        """
        Set the HackRF process (only one allowed at a time).
        
        Args:
            process: subprocess.Popen instance
            name: Process description
            attack_type: Type of attack (rf_jam, voice_broadcast, etc.)
        """
        with self._lock:
            if self._hackrf_process and self._hackrf_process.process.poll() is None:
                logger.warning(f"Terminating existing HackRF process: {self._hackrf_process.name}")
                self._terminate_process(self._hackrf_process.process, timeout=5)
            
            self._hackrf_process = ManagedProcess(
                process=process,
                name=name,
                attack_type=attack_type
            )
            logger.info(f"HackRF process started: {name}")
    
    def get_hackrf_process(self) -> Optional[subprocess.Popen]:
        """Get the current HackRF process."""
        with self._lock:
            if self._hackrf_process and self._hackrf_process.process.poll() is None:
                return self._hackrf_process.process
            return None
    
    def stop_hackrf_process(self, timeout: int = 5) -> bool:
        """
        Stop the HackRF process.
        
        Args:
            timeout: Termination timeout in seconds
            
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if self._hackrf_process:
                success = self._terminate_process(self._hackrf_process.process, timeout)
                logger.info(f"HackRF process stopped: {self._hackrf_process.name}")
                self._hackrf_process = None
                return success
            return True
    
    def add_attack_process(self, process: subprocess.Popen, name: str, attack_type: str = "unknown") -> None:
        """
        Add an attack process to tracking.
        
        Args:
            process: subprocess.Popen instance
            name: Process description
            attack_type: Type of attack
        """
        with self._lock:
            managed = ManagedProcess(
                process=process,
                name=name,
                attack_type=attack_type
            )
            self._active_processes.append(managed)
            logger.info(f"Attack process added: {name} ({attack_type})")
    
    def remove_completed_processes(self) -> int:
        """
        Remove completed processes from tracking.
        
        Returns:
            Number of processes removed
        """
        with self._lock:
            completed = [p for p in self._active_processes if p.process.poll() is not None]
            for proc in completed:
                self._active_processes.remove(proc)
                logger.debug(f"Removed completed process: {proc.name}")
            return len(completed)
    
    def get_active_processes(self) -> List[ManagedProcess]:
        """Get list of active processes."""
        with self._lock:
            return [p for p in self._active_processes if p.process.poll() is None]
    
    def stop_all_processes(self, timeout: int = 5) -> None:
        """
        Stop all tracked processes.
        
        Args:
            timeout: Termination timeout per process in seconds
        """
        with self._lock:
            logger.info(f"Stopping all processes ({len(self._active_processes)} active)")
            
            for managed in self._active_processes[:]:
                if managed.process.poll() is None:
                    self._terminate_process(managed.process, timeout)
                    logger.info(f"Stopped process: {managed.name}")
                self._active_processes.remove(managed)
            
            if self._hackrf_process:
                self.stop_hackrf_process(timeout)
    
    def _terminate_process(self, process: subprocess.Popen, timeout: int = 5) -> bool:
        """
        Terminate a process gracefully, then force kill if needed.
        
        Args:
            process: Process to terminate
            timeout: Timeout in seconds
            
        Returns:
            True if terminated successfully
        """
        if process.poll() is not None:
            return True
        
        try:
            process.terminate()
            process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Process didn't terminate gracefully, forcing kill (PID: {process.pid})")
            try:
                process.kill()
                process.wait(timeout=2)
                return True
            except Exception as e:
                logger.error(f"Failed to kill process: {e}")
                return False
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
            return False
    
    def get_process_count(self) -> dict:
        """Get count of active processes by type."""
        with self._lock:
            counts = {
                'hackrf': 1 if (self._hackrf_process and self._hackrf_process.process.poll() is None) else 0,
                'attacks': len([p for p in self._active_processes if p.process.poll() is None]),
                'total': 0
            }
            counts['total'] = counts['hackrf'] + counts['attacks']
            return counts
    
    def cleanup(self) -> None:
        """Cleanup all processes (alias for stop_all_processes)."""
        self.stop_all_processes()


_global_process_manager = None
_manager_lock = threading.Lock()


def get_process_manager() -> ProcessManager:
    """
    Get global ProcessManager instance (singleton pattern).
    
    Returns:
        ProcessManager instance
    """
    global _global_process_manager
    
    if _global_process_manager is None:
        with _manager_lock:
            if _global_process_manager is None:
                _global_process_manager = ProcessManager()
    
    return _global_process_manager
