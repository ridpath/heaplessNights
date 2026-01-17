"""
Autonomous Orchestrator for Obscura

Implements OODA loop (Observe-Orient-Decide-Act) decision logic
for intelligent attack chain generation based on target traits.

MITRE ATT&CK Mappings:
- T1595: Active Scanning
- T1592: Gather Victim Host Information
- T1590: Gather Victim Network Information
- T1498: Network Denial of Service
- T0885: Commonly Used Port
- T0884: Connection Proxy
"""

import json
import time
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging


class AttackPhase(Enum):
    """OODA Loop phases"""
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"


@dataclass
class TargetTrait:
    """Represents target characteristics for trait-based targeting"""
    device_type: str
    vendor: Optional[str] = None
    ssid_patterns: List[str] = field(default_factory=list)
    mac_prefix: Optional[str] = None
    dns_hosts: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    entropy_threshold: float = 7.0
    signal_strength: int = -100
    location: Optional[Dict[str, float]] = None


@dataclass
class AttackScore:
    """Score an attack's viability against a target"""
    plugin_name: str
    score: float
    confidence: float
    reason: str
    requirements_met: bool
    mitre_id: Optional[str] = None


@dataclass
class AttackChain:
    """Represents a sequence of attacks"""
    chain_id: str
    target_traits: TargetTrait
    attacks: List[str]
    scores: List[AttackScore]
    fallback_chains: List[List[str]] = field(default_factory=list)
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    start_time: Optional[float] = None
    end_time: Optional[float] = None


class AutonomousOrchestrator:
    """
    Autonomous attack orchestrator using OODA loop decision making.
    
    Implements:
    - Trait-based target profiling
    - Plugin scoring based on target characteristics
    - Attack chain generation with fallback strategies
    - OODA loop execution
    """
    
    def __init__(self, attack_orchestrator, simulate_mode: bool = False):
        """
        Initialize autonomous orchestrator.
        
        Args:
            attack_orchestrator: AttackOrchestrator instance with registered plugins
            simulate_mode: If True, no actual attacks are executed
        """
        self.orchestrator = attack_orchestrator
        self.simulate_mode = simulate_mode
        self.trait_db: Dict[str, TargetTrait] = {}
        self.attack_chains: List[AttackChain] = []
        self.current_phase: AttackPhase = AttackPhase.OBSERVE
        
        self.logger = logging.getLogger('obscura.orchestrator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def load_traits_from_file(self, traits_file: str) -> bool:
        """
        Load target traits from JSON file.
        
        Args:
            traits_file: Path to traits JSON file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        if not os.path.exists(traits_file):
            self.logger.error(f"Traits file not found: {traits_file}")
            return False
        
        try:
            with open(traits_file, 'r') as f:
                traits_data = json.load(f)
            
            for device_type, trait_dict in traits_data.items():
                trait = TargetTrait(
                    device_type=device_type,
                    ssid_patterns=trait_dict.get('ssid_patterns', []),
                    dns_hosts=trait_dict.get('dns_hosts', []),
                    entropy_threshold=trait_dict.get('entropy_threshold', 7.0),
                    vendor=trait_dict.get('vendor'),
                    mac_prefix=trait_dict.get('mac_prefix'),
                    services=trait_dict.get('services', []),
                    protocols=trait_dict.get('protocols', [])
                )
                self.trait_db[device_type] = trait
            
            self.logger.info(f"Loaded {len(self.trait_db)} target trait profiles")
            return True
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in traits file: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to load traits: {e}")
            return False
    
    def observe(self, target_data: Dict[str, Any]) -> TargetTrait:
        """
        OBSERVE phase: Gather target information.
        
        Args:
            target_data: Dictionary with target characteristics
            
        Returns:
            TargetTrait object
        """
        self.current_phase = AttackPhase.OBSERVE
        self.logger.info("OBSERVE: Gathering target information")
        
        device_type = target_data.get('device_type', 'unknown')
        
        target = TargetTrait(
            device_type=device_type,
            vendor=target_data.get('vendor'),
            ssid_patterns=target_data.get('ssid_patterns', []),
            mac_prefix=target_data.get('mac_prefix'),
            dns_hosts=target_data.get('dns_hosts', []),
            services=target_data.get('services', []),
            protocols=target_data.get('protocols', []),
            signal_strength=target_data.get('signal_strength', -100),
            location=target_data.get('location')
        )
        
        self.logger.info(f"  Device Type: {device_type}")
        self.logger.info(f"  Vendor: {target.vendor or 'Unknown'}")
        self.logger.info(f"  Services: {', '.join(target.services) if target.services else 'None'}")
        
        return target
    
    def orient(self, target: TargetTrait) -> List[str]:
        """
        ORIENT phase: Identify applicable attack vectors.
        
        Args:
            target: TargetTrait object from OBSERVE phase
            
        Returns:
            List of applicable attack plugin names
        """
        self.current_phase = AttackPhase.ORIENT
        self.logger.info("ORIENT: Identifying attack vectors")
        
        applicable_attacks = []
        
        device_type = target.device_type.lower()
        
        if device_type in ['drone', 'uav']:
            applicable_attacks.extend(['gps_spoof', 'rf_jam', 'drone_jam'])
        
        if device_type in ['camera', 'ipcam', 'webcam', 'surveillance']:
            applicable_attacks.extend([
                'camera_jam', 'mjpeg_inject', 'rtsp_inject',
                'camera_video_replay', 'mjpeg_image_inject', 'rtsp_image_inject'
            ])
        
        if device_type in ['wifi', 'router', 'ap', 'access_point']:
            applicable_attacks.extend([
                'wifi_deauth', 'rogue_ap', 'evil_twin', 'hybrid_deauth',
                'dns_spoof', 'arp_poison'
            ])
        
        if 'bluetooth' in target.services or device_type in ['ble', 'bluetooth', 'headset']:
            applicable_attacks.extend([
                'bluetooth_jam', 'ble_disrupt', 'bluetooth_hid_spoof',
                'ble_sniff_mitm', 'bluetooth_audio_replay'
            ])
        
        if device_type in ['satellite', 'sat', 'dvb']:
            applicable_attacks.extend(['satellite_disrupt', 'adsb_alert'])
        
        if device_type in ['iot', 'smart_device', 'sensor']:
            applicable_attacks.extend([
                'zigbee_disrupt', 'z_wave_exploit', 'iot_botnet',
                'firmware_exploit'
            ])
        
        if 'cellular' in target.protocols or device_type == 'cellular':
            applicable_attacks.extend(['cellular_intercept'])
        
        available_attacks = list(self.orchestrator.attack_vectors.keys())
        applicable_attacks = [a for a in applicable_attacks if a in available_attacks]
        
        self.logger.info(f"  Identified {len(applicable_attacks)} applicable attacks")
        for attack in applicable_attacks:
            self.logger.info(f"    - {attack}")
        
        return applicable_attacks
    
    def decide(self, target: TargetTrait, applicable_attacks: List[str]) -> AttackChain:
        """
        DECIDE phase: Score attacks and generate optimal chain.
        
        Args:
            target: TargetTrait object
            applicable_attacks: List of attack names from ORIENT phase
            
        Returns:
            AttackChain with scored attacks
        """
        self.current_phase = AttackPhase.DECIDE
        self.logger.info("DECIDE: Scoring attacks and generating chain")
        
        scores: List[AttackScore] = []
        
        for attack_name in applicable_attacks:
            score = self._score_attack(attack_name, target)
            scores.append(score)
        
        scores.sort(key=lambda x: x.score, reverse=True)
        
        primary_chain = [s.plugin_name for s in scores if s.score > 30.0]
        
        fallback_chains = self._generate_fallback_chains(scores, target)
        
        chain = AttackChain(
            chain_id=f"chain_{int(time.time())}",
            target_traits=target,
            attacks=primary_chain,
            scores=scores,
            fallback_chains=fallback_chains
        )
        
        self.logger.info(f"  Primary chain: {len(primary_chain)} attacks")
        for i, attack_name in enumerate(primary_chain[:5]):
            score_obj = next((s for s in scores if s.plugin_name == attack_name), None)
            if score_obj:
                self.logger.info(f"    {i+1}. {attack_name} (score: {score_obj.score:.1f})")
        
        self.logger.info(f"  Fallback chains: {len(fallback_chains)}")
        
        return chain
    
    def _score_attack(self, attack_name: str, target: TargetTrait) -> AttackScore:
        """
        Score an attack's effectiveness against a target.
        
        Args:
            attack_name: Name of attack to score
            target: TargetTrait object
            
        Returns:
            AttackScore object
        """
        base_score = 50.0
        confidence = 0.5
        reason = ""
        requirements_met = True
        mitre_id = None
        
        device_type = target.device_type.lower()
        
        if attack_name == 'gps_spoof':
            if device_type in ['drone', 'uav', 'gps']:
                base_score = 90.0
                confidence = 0.9
                reason = "GPS spoofing highly effective against drones"
                mitre_id = "T1499"
            else:
                base_score = 20.0
                confidence = 0.3
                reason = "Target unlikely to rely on GPS"
        
        elif attack_name == 'camera_jam':
            if device_type in ['camera', 'ipcam', 'webcam', 'surveillance']:
                base_score = 85.0
                confidence = 0.85
                reason = "RF jamming effective against wireless cameras"
                mitre_id = "T0885"
            else:
                base_score = 10.0
                reason = "Target is not a camera"
        
        elif attack_name in ['wifi_deauth', 'rogue_ap', 'evil_twin']:
            if device_type in ['wifi', 'router', 'ap', 'access_point'] or 'wifi' in target.protocols:
                base_score = 80.0
                confidence = 0.8
                reason = "Wi-Fi attacks viable against wireless infrastructure"
                mitre_id = "T1498"
            else:
                base_score = 30.0
                reason = "Target may have Wi-Fi connectivity"
        
        elif attack_name in ['bluetooth_jam', 'ble_disrupt', 'bluetooth_hid_spoof']:
            if 'bluetooth' in target.services or device_type in ['ble', 'bluetooth', 'headset']:
                base_score = 75.0
                confidence = 0.75
                reason = "Bluetooth attacks effective against BLE devices"
                mitre_id = "T0885"
            else:
                base_score = 15.0
                reason = "Target may not use Bluetooth"
        
        elif attack_name == 'satellite_disrupt':
            if device_type in ['satellite', 'sat', 'dvb']:
                base_score = 95.0
                confidence = 0.9
                reason = "Satellite jamming highly effective"
                mitre_id = "T0885"
            else:
                base_score = 5.0
                reason = "Target is not satellite-based"
        
        elif attack_name in ['mjpeg_inject', 'rtsp_inject']:
            if device_type in ['camera', 'ipcam', 'webcam']:
                base_score = 70.0
                confidence = 0.7
                reason = "Video injection viable against IP cameras"
                mitre_id = "T1557"
            else:
                base_score = 20.0
                reason = "Target may not use video streaming"
        
        elif attack_name in ['zigbee_disrupt', 'z_wave_exploit']:
            if device_type in ['iot', 'smart_device', 'sensor', 'smart_lock']:
                base_score = 80.0
                confidence = 0.75
                reason = "IoT protocol exploits effective"
                mitre_id = "T0885"
            else:
                base_score = 10.0
                reason = "Target unlikely to use IoT protocols"
        
        if target.signal_strength > -50:
            base_score += 10.0
            confidence += 0.1
        elif target.signal_strength < -80:
            base_score -= 20.0
            confidence -= 0.2
        
        confidence = max(0.0, min(1.0, confidence))
        
        return AttackScore(
            plugin_name=attack_name,
            score=base_score,
            confidence=confidence,
            reason=reason,
            requirements_met=requirements_met,
            mitre_id=mitre_id
        )
    
    def _generate_fallback_chains(self, scores: List[AttackScore], 
                                   target: TargetTrait) -> List[List[str]]:
        """
        Generate fallback attack chains if primary chain fails.
        
        Args:
            scores: List of AttackScore objects
            target: TargetTrait object
            
        Returns:
            List of fallback chains (each is a list of attack names)
        """
        fallback_chains = []
        
        medium_scores = [s for s in scores if 20.0 < s.score <= 30.0]
        if medium_scores:
            fallback_chains.append([s.plugin_name for s in medium_scores[:3]])
        
        low_scores = [s for s in scores if 10.0 < s.score <= 20.0]
        if low_scores:
            fallback_chains.append([s.plugin_name for s in low_scores[:3]])
        
        device_type = target.device_type.lower()
        if device_type in ['camera', 'ipcam']:
            fallback_chains.append(['vuln_scan', 'bettercap_mitm', 'dns_spoof'])
        elif device_type in ['drone', 'uav']:
            fallback_chains.append(['rf_jam', 'bluetooth_jam'])
        elif device_type in ['wifi', 'router']:
            fallback_chains.append(['wifi_deauth', 'arp_poison', 'ssl_strip'])
        
        return fallback_chains
    
    def act(self, chain: AttackChain, max_attacks: int = 5) -> bool:
        """
        ACT phase: Execute attack chain.
        
        Args:
            chain: AttackChain to execute
            max_attacks: Maximum number of attacks to execute
            
        Returns:
            True if chain succeeded, False otherwise
        """
        self.current_phase = AttackPhase.ACT
        self.logger.info("ACT: Executing attack chain")
        
        chain.start_time = time.time()
        
        attacks_to_run = chain.attacks[:max_attacks]
        
        for i, attack_name in enumerate(attacks_to_run):
            self.logger.info(f"  [{i+1}/{len(attacks_to_run)}] Executing: {attack_name}")
            
            if self.simulate_mode:
                self.logger.info(f"    [SIMULATE] Would execute {attack_name}")
                success = True
                execution_time = 0.1
            else:
                start = time.time()
                try:
                    success = self.orchestrator.execute(attack_name)
                except Exception as e:
                    self.logger.error(f"    [ERROR] {attack_name} failed: {e}")
                    success = False
                execution_time = time.time() - start
            
            chain.execution_log.append({
                'attack': attack_name,
                'success': success,
                'timestamp': time.time(),
                'execution_time': execution_time
            })
            
            if success:
                self.logger.info(f"    [SUCCESS] {attack_name} completed in {execution_time:.2f}s")
                chain.success = True
            else:
                self.logger.warning(f"    [FAILED] {attack_name}")
                
                if chain.fallback_chains:
                    self.logger.info("  Attempting fallback chain...")
                    fallback = chain.fallback_chains.pop(0)
                    chain.attacks = fallback + chain.attacks[i+1:]
                    attacks_to_run = chain.attacks[:max_attacks]
                    continue
                else:
                    self.logger.error("  No fallback chains available")
                    break
        
        chain.end_time = time.time()
        total_time = chain.end_time - chain.start_time
        
        self.logger.info(f"  Chain completed in {total_time:.2f}s")
        self.logger.info(f"  Success: {chain.success}")
        
        self.attack_chains.append(chain)
        
        return chain.success
    
    def run_ooda_loop(self, target_data: Dict[str, Any], max_attacks: int = 5) -> AttackChain:
        """
        Execute full OODA loop against a target.
        
        Args:
            target_data: Dictionary with target characteristics
            max_attacks: Maximum attacks to execute in ACT phase
            
        Returns:
            Completed AttackChain
        """
        self.logger.info("=== Starting OODA Loop ===")
        
        target = self.observe(target_data)
        
        applicable_attacks = self.orient(target)
        
        chain = self.decide(target, applicable_attacks)
        
        self.act(chain, max_attacks=max_attacks)
        
        self.logger.info("=== OODA Loop Complete ===")
        
        return chain
    
    def export_chain_to_json(self, chain: AttackChain, output_file: str) -> bool:
        """
        Export attack chain to JSON file.
        
        Args:
            chain: AttackChain to export
            output_file: Output file path
            
        Returns:
            True if exported successfully
        """
        try:
            chain_data = {
                'chain_id': chain.chain_id,
                'device_type': chain.target_traits.device_type,
                'vendor': chain.target_traits.vendor,
                'attacks': chain.attacks,
                'scores': [
                    {
                        'plugin': s.plugin_name,
                        'score': s.score,
                        'confidence': s.confidence,
                        'reason': s.reason,
                        'mitre_id': s.mitre_id
                    }
                    for s in chain.scores
                ],
                'execution_log': chain.execution_log,
                'fallback_chains': chain.fallback_chains,
                'success': chain.success,
                'start_time': chain.start_time,
                'end_time': chain.end_time,
                'duration': (chain.end_time - chain.start_time) if chain.end_time and chain.start_time else None
            }
            
            with open(output_file, 'w') as f:
                json.dump(chain_data, f, indent=2)
            
            self.logger.info(f"Exported attack chain to: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export chain: {e}")
            return False
    
    def export_chain_to_dot(self, chain: AttackChain, output_file: str) -> bool:
        """
        Export attack chain to DOT graph format.
        
        Args:
            chain: AttackChain to export
            output_file: Output .dot file path
            
        Returns:
            True if exported successfully
        """
        try:
            dot_content = "digraph AttackChain {\n"
            dot_content += "  rankdir=LR;\n"
            dot_content += "  node [shape=box, style=filled];\n"
            dot_content += "  graph [fontname=\"Arial\", fontsize=12];\n"
            dot_content += "  node [fontname=\"Arial\", fontsize=10];\n"
            dot_content += "  edge [fontname=\"Arial\", fontsize=8];\n\n"
            
            target_label = f"{chain.target_traits.device_type}"
            if chain.target_traits.vendor:
                target_label += f"\\n{chain.target_traits.vendor}"
            dot_content += f'  target [label="{target_label}", fillcolor=lightblue, shape=ellipse];\n\n'
            
            for i, attack in enumerate(chain.attacks):
                score_obj = next((s for s in chain.scores if s.plugin_name == attack), None)
                exec_log = next((log for log in chain.execution_log if log['attack'] == attack), None)
                
                if exec_log:
                    success = exec_log['success']
                    color = "lightgreen" if success else "lightcoral"
                    status = "SUCCESS" if success else "FAILED"
                    exec_time = exec_log.get('execution_time', 0)
                    label = f"{attack}\\n{status}\\n{exec_time:.2f}s"
                elif score_obj:
                    color = "lightgreen" if score_obj.score > 70 else "yellow" if score_obj.score > 40 else "lightcoral"
                    label = f"{attack}\\nscore: {score_obj.score:.1f}"
                    if score_obj.mitre_id:
                        label += f"\\n{score_obj.mitre_id}"
                else:
                    color = "lightgray"
                    label = attack
                
                dot_content += f'  attack_{i} [label="{label}", fillcolor={color}];\n'
            
            dot_content += "\n  // Attack chain flow\n"
            if chain.attacks:
                dot_content += f'  target -> attack_0 [label="target"];\n'
                for i in range(len(chain.attacks) - 1):
                    dot_content += f'  attack_{i} -> attack_{i+1};\n'
            
            if chain.fallback_chains:
                dot_content += "\n  // Fallback chains\n"
                for j, fallback in enumerate(chain.fallback_chains):
                    fallback_label = f"Fallback {j+1}\\n" + "\\n".join(fallback[:3])
                    dot_content += f'  fallback_{j} [label="{fallback_label}", shape=diamond, fillcolor=orange];\n'
                    if chain.attacks:
                        dot_content += f'  attack_0 -> fallback_{j} [style=dashed, label="on fail"];\n'
            
            if chain.success:
                dot_content += '\n  result [label="SUCCESS", fillcolor=green, fontcolor=white, shape=box];\n'
                if chain.attacks:
                    dot_content += f'  attack_{len(chain.attacks)-1} -> result;\n'
            elif chain.execution_log:
                dot_content += '\n  result [label="FAILED", fillcolor=red, fontcolor=white, shape=box];\n'
                if chain.attacks:
                    last_attack = len([log for log in chain.execution_log]) - 1
                    dot_content += f'  attack_{last_attack} -> result;\n'
            
            dot_content += "}\n"
            
            with open(output_file, 'w') as f:
                f.write(dot_content)
            
            self.logger.info(f"Exported attack chain graph to: {output_file}")
            
            if output_file.endswith('.dot'):
                svg_file = output_file.replace('.dot', '.svg')
                try:
                    import subprocess
                    result = subprocess.run(['dot', '-Tsvg', output_file, '-o', svg_file], 
                                 check=True, timeout=10, capture_output=True, text=True)
                    self.logger.info(f"Converted to SVG: {svg_file}")
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                    self.logger.warning(f"graphviz not available: {e}")
                    self.logger.warning("DOT file created but not converted to SVG")
                    self.logger.info("Install graphviz to enable SVG export: apt-get install graphviz (Linux) or brew install graphviz (macOS)")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export DOT graph: {e}")
            return False
