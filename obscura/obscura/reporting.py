"""
Reporting module for Obscura attack chain execution.

Provides structured logging and report generation in multiple formats:
- JSON: Machine-readable attack chain data
- Markdown: Human-readable summary with MITRE ATT&CK mapping
- DOT/SVG: Visual attack graph representation
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


class AttackReporter:
    """
    Generate comprehensive attack reports with MITRE ATT&CK mapping.
    """
    
    MITRE_ATTACK_DB = {
        'gps_spoof': {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
        'camera_jam': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'wifi_deauth': {'id': 'T1498', 'name': 'Network Denial of Service', 'tactic': 'Impact'},
        'rogue_ap': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'evil_twin': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'bluetooth_jam': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'ble_disrupt': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'satellite_disrupt': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'mjpeg_inject': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'rtsp_inject': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'dns_spoof': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'arp_poison': {'id': 'T1557.002', 'name': 'ARP Cache Poisoning', 'tactic': 'Collection'},
        'zigbee_disrupt': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'z_wave_exploit': {'id': 'T0885', 'name': 'Commonly Used Port', 'tactic': 'Command and Control'},
        'rf_jam': {'id': 'T0809', 'name': 'Inhibit Response Function', 'tactic': 'Inhibit Response Function'},
        'adsb_replay': {'id': 'T1557', 'name': 'Adversary-in-the-Middle', 'tactic': 'Collection'},
        'cellular_intercept': {'id': 'T1040', 'name': 'Network Sniffing', 'tactic': 'Discovery'},
    }
    
    def __init__(self, output_dir: str = 'logs'):
        """
        Initialize reporter.
        
        Args:
            output_dir: Directory to save reports (default: logs/)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def calculate_chain_score(self, chain: Any) -> float:
        """
        Calculate overall chain effectiveness score (0-100).
        
        Factors:
        - Individual attack scores
        - Execution success rate
        - Chain completion vs planned
        
        Args:
            chain: AttackChain object
            
        Returns:
            Chain score (0-100)
        """
        if not chain.attacks:
            return 0.0
        
        avg_attack_score = sum(s.score for s in chain.scores) / len(chain.scores) if chain.scores else 50.0
        
        if chain.execution_log:
            success_count = sum(1 for log in chain.execution_log if log.get('success', False))
            execution_success_rate = (success_count / len(chain.execution_log)) * 100
        else:
            execution_success_rate = 0.0
        
        completion_bonus = 20.0 if chain.success else 0.0
        
        chain_score = (avg_attack_score * 0.5) + (execution_success_rate * 0.3) + completion_bonus
        
        return min(100.0, max(0.0, chain_score))
    
    def generate_markdown_report(self, chain: Any, output_file: Optional[str] = None) -> str:
        """
        Generate Markdown report for attack chain.
        
        Args:
            chain: AttackChain object
            output_file: Optional output file path (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"attack_report_{timestamp}.md"
        else:
            output_file = Path(output_file)
        
        md_content = []
        
        md_content.append("# Obscura Attack Chain Report\n")
        md_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md_content.append(f"**Chain ID:** {chain.chain_id}\n")
        md_content.append(f"**Status:** {'SUCCESS' if chain.success else 'FAILED'}\n")
        
        chain_score = self.calculate_chain_score(chain)
        md_content.append(f"**Chain Score:** {chain_score:.1f}/100\n")
        
        if chain.start_time and chain.end_time:
            duration = chain.end_time - chain.start_time
            md_content.append(f"**Duration:** {duration:.2f} seconds\n")
        
        md_content.append("\n---\n\n")
        
        md_content.append("## Target Information\n\n")
        md_content.append(f"- **Device Type:** {chain.target_traits.device_type}\n")
        
        if chain.target_traits.vendor:
            md_content.append(f"- **Vendor:** {chain.target_traits.vendor}\n")
        
        if chain.target_traits.services:
            md_content.append(f"- **Services:** {', '.join(chain.target_traits.services)}\n")
        
        if chain.target_traits.protocols:
            md_content.append(f"- **Protocols:** {', '.join(chain.target_traits.protocols)}\n")
        
        md_content.append(f"- **Signal Strength:** {chain.target_traits.signal_strength} dBm\n")
        
        if chain.target_traits.location:
            lat = chain.target_traits.location.get('lat', 'N/A')
            lon = chain.target_traits.location.get('lon', 'N/A')
            md_content.append(f"- **Location:** {lat}, {lon}\n")
        
        md_content.append("\n---\n\n")
        
        md_content.append("## Attack Chain\n\n")
        md_content.append(f"**Primary Chain:** {len(chain.attacks)} attacks\n\n")
        
        for i, attack_name in enumerate(chain.attacks):
            md_content.append(f"### {i+1}. {attack_name}\n\n")
            
            score_obj = next((s for s in chain.scores if s.plugin_name == attack_name), None)
            if score_obj:
                md_content.append(f"- **Score:** {score_obj.score:.1f}/100\n")
                md_content.append(f"- **Confidence:** {score_obj.confidence:.0%}\n")
                md_content.append(f"- **Reason:** {score_obj.reason}\n")
                
                if score_obj.mitre_id:
                    mitre_info = self.MITRE_ATTACK_DB.get(attack_name, {})
                    if mitre_info:
                        md_content.append(f"- **MITRE ATT&CK:** [{mitre_info['id']}](https://attack.mitre.org/techniques/{mitre_info['id'].replace('.', '/')}) - {mitre_info['name']}\n")
                        md_content.append(f"- **Tactic:** {mitre_info['tactic']}\n")
                    else:
                        md_content.append(f"- **MITRE ATT&CK:** {score_obj.mitre_id}\n")
            
            exec_log = next((log for log in chain.execution_log if log['attack'] == attack_name), None)
            if exec_log:
                status = 'SUCCESS' if exec_log['success'] else 'FAILED'
                md_content.append(f"- **Status:** {status}\n")
                md_content.append(f"- **Execution Time:** {exec_log.get('execution_time', 0):.2f}s\n")
                md_content.append(f"- **Timestamp:** {datetime.fromtimestamp(exec_log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            md_content.append("\n")
        
        if chain.fallback_chains:
            md_content.append("\n---\n\n")
            md_content.append("## Fallback Chains\n\n")
            md_content.append(f"{len(chain.fallback_chains)} fallback chain(s) available\n\n")
            
            for i, fallback in enumerate(chain.fallback_chains):
                md_content.append(f"### Fallback Chain {i+1}\n\n")
                for attack in fallback:
                    md_content.append(f"- {attack}\n")
                md_content.append("\n")
        
        md_content.append("\n---\n\n")
        md_content.append("## MITRE ATT&CK Summary\n\n")
        
        mitre_techniques = {}
        for attack_name in chain.attacks:
            mitre_info = self.MITRE_ATTACK_DB.get(attack_name)
            if mitre_info:
                technique_id = mitre_info['id']
                if technique_id not in mitre_techniques:
                    mitre_techniques[technique_id] = {
                        'name': mitre_info['name'],
                        'tactic': mitre_info['tactic'],
                        'attacks': []
                    }
                mitre_techniques[technique_id]['attacks'].append(attack_name)
        
        if mitre_techniques:
            md_content.append("| Technique ID | Technique Name | Tactic | Attacks |\n")
            md_content.append("|--------------|----------------|--------|----------|\n")
            
            for tech_id, info in sorted(mitre_techniques.items()):
                attacks_str = ', '.join(info['attacks'])
                md_content.append(f"| {tech_id} | {info['name']} | {info['tactic']} | {attacks_str} |\n")
        else:
            md_content.append("*No MITRE ATT&CK techniques mapped*\n")
        
        md_content.append("\n---\n\n")
        md_content.append("## Execution Log\n\n")
        
        if chain.execution_log:
            md_content.append("| # | Attack | Status | Time (s) | Timestamp |\n")
            md_content.append("|---|--------|--------|----------|------------|\n")
            
            for i, log in enumerate(chain.execution_log):
                status = '[OK]' if log['success'] else '[FAIL]'
                timestamp = datetime.fromtimestamp(log['timestamp']).strftime('%H:%M:%S')
                exec_time = log.get('execution_time', 0)
                md_content.append(f"| {i+1} | {log['attack']} | {status} | {exec_time:.2f} | {timestamp} |\n")
        else:
            md_content.append("*No execution logs available*\n")
        
        md_content.append("\n---\n\n")
        md_content.append(f"*Report generated by Obscura v0.1.0*\n")
        
        report_text = ''.join(md_content)
        
        output_file.write_text(report_text, encoding='utf-8')
        
        return str(output_file)
    
    def save_json_log(self, chain: Any, output_file: Optional[str] = None) -> str:
        """
        Save attack chain as JSON log.
        
        Args:
            chain: AttackChain object
            output_file: Optional output file path
            
        Returns:
            Path to saved JSON file
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"chain_{timestamp}.json"
        else:
            output_file = Path(output_file)
        
        chain_score = self.calculate_chain_score(chain)
        
        chain_data = {
            'chain_id': chain.chain_id,
            'timestamp': datetime.now().isoformat(),
            'chain_score': chain_score,
            'target': {
                'device_type': chain.target_traits.device_type,
                'vendor': chain.target_traits.vendor,
                'services': chain.target_traits.services,
                'protocols': chain.target_traits.protocols,
                'signal_strength': chain.target_traits.signal_strength,
                'location': chain.target_traits.location
            },
            'attacks': [
                {
                    'name': s.plugin_name,
                    'score': s.score,
                    'confidence': s.confidence,
                    'reason': s.reason,
                    'requirements_met': s.requirements_met,
                    'mitre_id': s.mitre_id,
                    'mitre_info': self.MITRE_ATTACK_DB.get(s.plugin_name)
                }
                for s in chain.scores
            ],
            'execution_log': chain.execution_log,
            'fallback_chains': chain.fallback_chains,
            'success': chain.success,
            'start_time': chain.start_time,
            'end_time': chain.end_time,
            'duration_seconds': (chain.end_time - chain.start_time) if chain.end_time and chain.start_time else None
        }
        
        with open(output_file, 'w') as f:
            json.dump(chain_data, f, indent=2)
        
        return str(output_file)
    
    def generate_mitre_matrix(self, chains: List[Any]) -> Dict[str, Any]:
        """
        Generate MITRE ATT&CK matrix coverage summary for multiple chains.
        
        Args:
            chains: List of AttackChain objects
            
        Returns:
            Dictionary with MITRE matrix coverage data
        """
        tactics = {}
        techniques = {}
        
        for chain in chains:
            for attack_name in chain.attacks:
                mitre_info = self.MITRE_ATTACK_DB.get(attack_name)
                if mitre_info:
                    tactic = mitre_info['tactic']
                    technique_id = mitre_info['id']
                    
                    if tactic not in tactics:
                        tactics[tactic] = {'techniques': set(), 'attacks': []}
                    tactics[tactic]['techniques'].add(technique_id)
                    tactics[tactic]['attacks'].append(attack_name)
                    
                    if technique_id not in techniques:
                        techniques[technique_id] = {
                            'name': mitre_info['name'],
                            'tactic': tactic,
                            'count': 0
                        }
                    techniques[technique_id]['count'] += 1
        
        for tactic in tactics:
            tactics[tactic]['techniques'] = list(tactics[tactic]['techniques'])
        
        return {
            'tactics': {k: {'technique_count': len(v['techniques']), 'techniques': v['techniques']} 
                       for k, v in tactics.items()},
            'techniques': techniques,
            'total_tactics': len(tactics),
            'total_techniques': len(techniques),
            'coverage_summary': f"{len(techniques)} techniques across {len(tactics)} tactics"
        }
    
    def generate_campaign_report(self, chains: List[Any], campaign_name: str = "Obscura Campaign") -> str:
        """
        Generate comprehensive campaign report covering multiple attack chains.
        
        Args:
            chains: List of AttackChain objects
            campaign_name: Name of the campaign
            
        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f"campaign_report_{timestamp}.md"
        
        md_content = []
        
        md_content.append(f"# {campaign_name}\n")
        md_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md_content.append(f"**Total Chains:** {len(chains)}\n")
        
        successful = sum(1 for c in chains if c.success)
        md_content.append(f"**Successful:** {successful}/{len(chains)} ({successful/len(chains)*100:.1f}%)\n")
        
        md_content.append("\n---\n\n")
        
        md_content.append("## Chain Summary\n\n")
        md_content.append("| Chain ID | Device Type | Attacks | Status | Duration |\n")
        md_content.append("|----------|-------------|---------|--------|----------|\n")
        
        for chain in chains:
            status = 'SUCCESS' if chain.success else 'FAILED'
            duration = (chain.end_time - chain.start_time) if chain.end_time and chain.start_time else 0
            md_content.append(f"| {chain.chain_id} | {chain.target_traits.device_type} | {len(chain.attacks)} | {status} | {duration:.2f}s |\n")
        
        md_content.append("\n---\n\n")
        
        mitre_matrix = self.generate_mitre_matrix(chains)
        
        md_content.append("## MITRE ATT&CK Coverage\n\n")
        md_content.append(f"**Coverage:** {mitre_matrix['coverage_summary']}\n\n")
        
        md_content.append("### Tactics\n\n")
        for tactic, data in sorted(mitre_matrix['tactics'].items()):
            md_content.append(f"- **{tactic}:** {data['technique_count']} techniques\n")
        
        md_content.append("\n### Techniques\n\n")
        md_content.append("| Technique ID | Technique Name | Tactic | Usage Count |\n")
        md_content.append("|--------------|----------------|--------|-------------|\n")
        
        for tech_id, info in sorted(mitre_matrix['techniques'].items()):
            md_content.append(f"| {tech_id} | {info['name']} | {info['tactic']} | {info['count']} |\n")
        
        md_content.append("\n---\n\n")
        md_content.append(f"*Campaign report generated by Obscura v0.1.0*\n")
        
        report_text = ''.join(md_content)
        output_file.write_text(report_text, encoding='utf-8')
        
        return str(output_file)
    
    def generate_html_report(self, chain: Any, output_file: Optional[str] = None) -> str:
        """
        Generate HTML report for attack chain.
        
        Args:
            chain: AttackChain object
            output_file: Optional output file path (auto-generated if None)
            
        Returns:
            Path to generated HTML report
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"attack_report_{timestamp}.html"
        else:
            output_file = Path(output_file)
        
        html_content = []
        
        html_content.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Obscura Attack Chain Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #e0e0e0;
            background: #0a0a0a;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .meta {
            font-size: 0.9em;
            opacity: 0.95;
        }
        
        .section {
            padding: 30px;
            border-bottom: 1px solid #333;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .section h3 {
            color: #8b9dc3;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .info-item {
            background: #252525;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }
        
        .info-item label {
            display: block;
            color: #999;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }
        
        .info-item value {
            display: block;
            color: #e0e0e0;
            font-size: 1.1em;
            font-weight: 500;
        }
        
        .attack-card {
            background: #252525;
            border: 1px solid #333;
            border-radius: 5px;
            padding: 20px;
            margin: 15px 0;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .attack-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
        }
        
        .attack-card h3 {
            margin-top: 0;
            color: #667eea;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 5px 5px 5px 0;
        }
        
        .badge-success {
            background: #10b981;
            color: white;
        }
        
        .badge-failure {
            background: #ef4444;
            color: white;
        }
        
        .badge-mitre {
            background: #764ba2;
            color: white;
        }
        
        .badge-tactic {
            background: #3b82f6;
            color: white;
        }
        
        .progress-bar {
            background: #333;
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            transition: width 0.3s;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #252525;
            border-radius: 5px;
            overflow: hidden;
        }
        
        thead {
            background: #333;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #2a2a2a;
        }
        
        th {
            color: #667eea;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover {
            background: #2a2a2a;
        }
        
        .metric {
            text-align: center;
            padding: 20px;
            background: #252525;
            border-radius: 5px;
            border: 1px solid #333;
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            display: block;
        }
        
        .metric-label {
            font-size: 0.9em;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            background: #0f0f0f;
        }
        
        .log-entry {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            padding: 8px;
            margin: 5px 0;
            background: #0f0f0f;
            border-left: 3px solid #667eea;
            border-radius: 3px;
        }
        
        .log-success {
            border-left-color: #10b981;
        }
        
        .log-failure {
            border-left-color: #ef4444;
        }
    </style>
</head>
<body>
    <div class="container">
""")
        
        status_class = "success" if chain.success else "failure"
        status_text = "SUCCESS" if chain.success else "FAILED"
        
        html_content.append(f"""        <div class="header">
            <h1>Obscura Attack Chain Report</h1>
            <div class="meta">
                <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
                <strong>Chain ID:</strong> {chain.chain_id} | 
                <strong>Status:</strong> <span class="badge badge-{status_class}">{status_text}</span>
            </div>
        </div>
""")
        
        html_content.append("""        <div class="section">
            <h2>📊 Target Information</h2>
            <div class="info-grid">
""")
        
        html_content.append(f"""                <div class="info-item">
                    <label>Device Type</label>
                    <value>{chain.target_traits.device_type}</value>
                </div>
""")
        
        if chain.target_traits.vendor:
            html_content.append(f"""                <div class="info-item">
                    <label>Vendor</label>
                    <value>{chain.target_traits.vendor}</value>
                </div>
""")
        
        html_content.append(f"""                <div class="info-item">
                    <label>Signal Strength</label>
                    <value>{chain.target_traits.signal_strength} dBm</value>
                </div>
""")
        
        if chain.start_time and chain.end_time:
            duration = chain.end_time - chain.start_time
            html_content.append(f"""                <div class="info-item">
                    <label>Duration</label>
                    <value>{duration:.2f} seconds</value>
                </div>
""")
        
        if chain.target_traits.services:
            services_str = ', '.join(chain.target_traits.services)
            html_content.append(f"""                <div class="info-item">
                    <label>Services</label>
                    <value>{services_str}</value>
                </div>
""")
        
        if chain.target_traits.protocols:
            protocols_str = ', '.join(chain.target_traits.protocols)
            html_content.append(f"""                <div class="info-item">
                    <label>Protocols</label>
                    <value>{protocols_str}</value>
                </div>
""")
        
        html_content.append("""            </div>
        </div>
""")
        
        html_content.append(f"""        <div class="section">
            <h2>⚔️ Attack Chain ({len(chain.attacks)} attacks)</h2>
""")
        
        for i, attack_name in enumerate(chain.attacks):
            score_obj = next((s for s in chain.scores if s.plugin_name == attack_name), None)
            exec_log = next((log for log in chain.execution_log if log['attack'] == attack_name), None)
            
            html_content.append(f"""            <div class="attack-card">
                <h3>{i+1}. {attack_name}</h3>
""")
            
            if score_obj:
                confidence_pct = score_obj.confidence * 100
                html_content.append(f"""                <div class="progress-bar">
                    <div class="progress-fill" style="width: {score_obj.score}%"></div>
                </div>
                <p><strong>Score:</strong> {score_obj.score:.1f}/100 | <strong>Confidence:</strong> {confidence_pct:.0f}%</p>
                <p><strong>Reason:</strong> {score_obj.reason}</p>
""")
                
                if score_obj.mitre_id:
                    mitre_info = self.MITRE_ATTACK_DB.get(attack_name, {})
                    if mitre_info:
                        mitre_url = f"https://attack.mitre.org/techniques/{mitre_info['id'].replace('.', '/')}"
                        html_content.append(f"""                <div style="margin-top: 10px;">
                    <a href="{mitre_url}" class="badge badge-mitre" target="_blank">{mitre_info['id']} - {mitre_info['name']}</a>
                    <span class="badge badge-tactic">{mitre_info['tactic']}</span>
                </div>
""")
            
            if exec_log:
                status_badge = "badge-success" if exec_log['success'] else "badge-failure"
                status_icon = "[OK]" if exec_log['success'] else "[FAIL]"
                timestamp_str = datetime.fromtimestamp(exec_log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                html_content.append(f"""                <div style="margin-top: 15px;">
                    <span class="badge {status_badge}">{exec_log['success'] and 'SUCCESS' or 'FAILED'}</span>
                    <span style="color: #999; margin-left: 10px;">Execution Time: {exec_log.get('execution_time', 0):.2f}s</span>
                    <span style="color: #999; margin-left: 10px;">Timestamp: {timestamp_str}</span>
                </div>
""")
            
            html_content.append("""            </div>
""")
        
        html_content.append("""        </div>
""")
        
        mitre_techniques = {}
        for attack_name in chain.attacks:
            mitre_info = self.MITRE_ATTACK_DB.get(attack_name)
            if mitre_info:
                technique_id = mitre_info['id']
                if technique_id not in mitre_techniques:
                    mitre_techniques[technique_id] = {
                        'name': mitre_info['name'],
                        'tactic': mitre_info['tactic'],
                        'attacks': []
                    }
                mitre_techniques[technique_id]['attacks'].append(attack_name)
        
        if mitre_techniques:
            html_content.append("""        <div class="section">
            <h2>MITRE ATT&CK Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Attacks</th>
                    </tr>
                </thead>
                <tbody>
""")
            
            for tech_id, info in sorted(mitre_techniques.items()):
                attacks_str = ', '.join(info['attacks'])
                html_content.append(f"""                    <tr>
                        <td><span class="badge badge-mitre">{tech_id}</span></td>
                        <td>{info['name']}</td>
                        <td><span class="badge badge-tactic">{info['tactic']}</span></td>
                        <td>{attacks_str}</td>
                    </tr>
""")
            
            html_content.append("""                </tbody>
            </table>
        </div>
""")
        
        if chain.execution_log:
            html_content.append("""        <div class="section">
            <h2>📋 Execution Log</h2>
""")
            
            for i, log in enumerate(chain.execution_log):
                log_class = "log-success" if log['success'] else "log-failure"
                status_icon = "[OK]" if log['success'] else "[FAIL]"
                timestamp_str = datetime.fromtimestamp(log['timestamp']).strftime('%H:%M:%S')
                exec_time = log.get('execution_time', 0)
                
                html_content.append(f"""            <div class="log-entry {log_class}">
                [{timestamp_str}] {status_icon} {log['attack']} - {exec_time:.2f}s
            </div>
""")
            
            html_content.append("""        </div>
""")
        
        html_content.append(f"""        <div class="footer">
            <p>Report generated by <strong>Obscura v0.1.0</strong> - Multi-Vector Adversarial Framework</p>
            <p style="margin-top: 5px; font-size: 0.85em;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
""")
        
        report_html = ''.join(html_content)
        output_file.write_text(report_html, encoding='utf-8')
        
        return str(output_file)
    
    def generate_pdf_report(self, chain: Any, output_file: Optional[str] = None) -> str:
        """
        Generate PDF report from HTML.
        
        Args:
            chain: AttackChain object
            output_file: Optional output file path (auto-generated if None)
            
        Returns:
            Path to generated PDF report
        """
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("WeasyPrint not installed. Install with: pip install weasyprint")
        
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"attack_report_{timestamp}.pdf"
        else:
            output_file = Path(output_file)
        
        html_file = self.output_dir / f"temp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        self.generate_html_report(chain, str(html_file))
        
        HTML(filename=str(html_file)).write_pdf(str(output_file))
        
        html_file.unlink()
        
        return str(output_file)
