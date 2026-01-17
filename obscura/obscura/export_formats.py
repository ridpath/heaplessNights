"""
Export Formats for Red Team Reporting

Supports industry-standard formats:
- ATT&CK Navigator JSON (MITRE)
- STIX 2.1 (Structured Threat Information Expression)
- CSV (Excel-ready analysis)
- SQLite (queryable database)
- MISP (Malware Information Sharing Platform)
- Elasticsearch/Kibana JSON
- Timeline CSV (for forensic reconstruction)

MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
"""

import json
import csv
import sqlite3
import hashlib
import uuid
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set


class ATTACKNavigatorExporter:
    """Export to ATT&CK Navigator JSON format"""
    
    NAVIGATOR_VERSION = "4.9"
    LAYER_VERSION = "4.5"
    
    def __init__(self, name: str = "Obscura Operation", description: str = ""):
        self.name = name
        self.description = description
        self.techniques: Dict[str, Dict[str, Any]] = {}
    
    def add_technique(self, technique_id: str, attack_name: str, score: float,
                     comment: str = "", metadata: Optional[Dict] = None) -> None:
        """Add technique to navigator layer"""
        if technique_id not in self.techniques:
            self.techniques[technique_id] = {
                'techniqueID': technique_id,
                'score': 0,
                'color': '',
                'comment': '',
                'enabled': True,
                'metadata': [],
                'showSubtechniques': True
            }
        
        self.techniques[technique_id]['score'] = max(
            self.techniques[technique_id]['score'],
            int(score)
        )
        
        if comment:
            existing_comment = self.techniques[technique_id]['comment']
            self.techniques[technique_id]['comment'] = f"{existing_comment}\n{attack_name}: {comment}".strip()
        
        if metadata:
            self.techniques[technique_id]['metadata'].append({
                'name': attack_name,
                'value': json.dumps(metadata)
            })
        
        if score >= 80:
            self.techniques[technique_id]['color'] = '#ff6666'
        elif score >= 60:
            self.techniques[technique_id]['color'] = '#ffcc66'
        else:
            self.techniques[technique_id]['color'] = '#66ff66'
    
    def export(self, output_file: str) -> None:
        """Export to ATT&CK Navigator JSON"""
        layer = {
            'name': self.name,
            'versions': {
                'navigator': self.NAVIGATOR_VERSION,
                'layer': self.LAYER_VERSION,
                'attack': '14'
            },
            'domain': 'enterprise-attack',
            'description': self.description,
            'filters': {
                'platforms': ['Windows', 'Linux', 'macOS', 'Network', 'PRE']
            },
            'sorting': 3,
            'layout': {
                'layout': 'side',
                'aggregateFunction': 'average',
                'showID': True,
                'showName': True,
                'showAggregateScores': True,
                'countUnscored': False
            },
            'hideDisabled': False,
            'techniques': list(self.techniques.values()),
            'gradient': {
                'colors': ['#66ff66', '#ffcc66', '#ff6666'],
                'minValue': 0,
                'maxValue': 100
            },
            'legendItems': [
                {'label': 'Low Impact', 'color': '#66ff66'},
                {'label': 'Medium Impact', 'color': '#ffcc66'},
                {'label': 'High Impact', 'color': '#ff6666'}
            ],
            'metadata': [],
            'links': [],
            'showTacticRowBackground': True,
            'tacticRowBackground': '#dddddd',
            'selectTechniquesAcrossTactics': True
        }
        
        with open(output_file, 'w') as f:
            json.dump(layer, f, indent=2)


class STIXExporter:
    """Export to STIX 2.1 format"""
    
    STIX_VERSION = "2.1"
    
    def __init__(self, identity_name: str = "Obscura Red Team"):
        self.identity_name = identity_name
        self.identity_id = f"identity--{uuid.uuid4()}"
        self.objects = []
        
        self.objects.append({
            'type': 'identity',
            'spec_version': self.STIX_VERSION,
            'id': self.identity_id,
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': identity_name,
            'identity_class': 'organization'
        })
    
    def add_attack_pattern(self, technique_id: str, technique_name: str,
                          description: str, tactic: str) -> str:
        """Add attack pattern to STIX bundle"""
        pattern_id = f"attack-pattern--{uuid.uuid4()}"
        
        external_refs = [{
            'source_name': 'mitre-attack',
            'external_id': technique_id,
            'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
        }]
        
        self.objects.append({
            'type': 'attack-pattern',
            'spec_version': self.STIX_VERSION,
            'id': pattern_id,
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'name': technique_name,
            'description': description,
            'kill_chain_phases': [{
                'kill_chain_name': 'mitre-attack',
                'phase_name': tactic.lower().replace(' ', '-')
            }],
            'external_references': external_refs
        })
        
        return pattern_id
    
    def add_indicator(self, pattern: str, pattern_type: str,
                     description: str, labels: Optional[List[str]] = None) -> str:
        """Add indicator to STIX bundle"""
        indicator_id = f"indicator--{uuid.uuid4()}"
        
        self.objects.append({
            'type': 'indicator',
            'spec_version': self.STIX_VERSION,
            'id': indicator_id,
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'pattern': pattern,
            'pattern_type': pattern_type,
            'valid_from': datetime.now(timezone.utc).isoformat(),
            'description': description,
            'labels': labels or ['malicious-activity']
        })
        
        return indicator_id
    
    def add_relationship(self, source_id: str, target_id: str, relationship_type: str) -> None:
        """Add relationship between STIX objects"""
        self.objects.append({
            'type': 'relationship',
            'spec_version': self.STIX_VERSION,
            'id': f"relationship--{uuid.uuid4()}",
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'relationship_type': relationship_type,
            'source_ref': source_id,
            'target_ref': target_id
        })
    
    def export(self, output_file: str) -> None:
        """Export to STIX bundle"""
        bundle = {
            'type': 'bundle',
            'id': f"bundle--{uuid.uuid4()}",
            'objects': self.objects
        }
        
        with open(output_file, 'w') as f:
            json.dump(bundle, f, indent=2)


class CSVExporter:
    """Export to CSV for Excel analysis"""
    
    @staticmethod
    def export_attacks(attacks: List[Dict[str, Any]], output_file: str) -> None:
        """Export attacks to CSV"""
        if not attacks:
            return
        
        fieldnames = [
            'timestamp', 'chain_id', 'attack_name', 'success', 'score',
            'confidence', 'mitre_id', 'tactic', 'execution_time',
            'target_type', 'target_vendor'
        ]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for attack in attacks:
                writer.writerow({
                    'timestamp': datetime.fromtimestamp(attack.get('timestamp', 0)).isoformat(),
                    'chain_id': attack.get('chain_id', ''),
                    'attack_name': attack.get('name', attack.get('attack_name', '')),
                    'success': attack.get('success', False),
                    'score': attack.get('score', 0),
                    'confidence': attack.get('confidence', 0),
                    'mitre_id': attack.get('mitre_id', ''),
                    'tactic': attack.get('tactic', ''),
                    'execution_time': attack.get('execution_time', 0),
                    'target_type': attack.get('target_type', ''),
                    'target_vendor': attack.get('target_vendor', '')
                })
    
    @staticmethod
    def export_timeline(events: List[Dict[str, Any]], output_file: str) -> None:
        """Export timeline for forensic reconstruction"""
        if not events:
            return
        
        fieldnames = [
            'timestamp', 'event_type', 'source', 'destination',
            'action', 'result', 'details', 'operator', 'session_id'
        ]
        
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', 0))
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in sorted_events:
                writer.writerow({
                    'timestamp': datetime.fromtimestamp(event.get('timestamp', 0)).isoformat(),
                    'event_type': event.get('event_type', ''),
                    'source': event.get('source', ''),
                    'destination': event.get('destination', ''),
                    'action': event.get('action', ''),
                    'result': event.get('result', ''),
                    'details': event.get('details', ''),
                    'operator': event.get('operator', ''),
                    'session_id': event.get('session_id', '')
                })
    
    @staticmethod
    def export_evidence(evidence_list: List[Dict[str, Any]], output_file: str) -> None:
        """Export evidence chain of custody"""
        if not evidence_list:
            return
        
        fieldnames = [
            'artifact_id', 'timestamp', 'operator', 'artifact_type',
            'file_path', 'data_hash', 'description', 'chain_id',
            'pcap_reference', 'screenshot_reference'
        ]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in evidence_list:
                writer.writerow(evidence)


class SQLiteExporter:
    """Export to SQLite database for complex queries"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_schema()
    
    def _init_schema(self) -> None:
        """Initialize database schema"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                operation_name TEXT,
                start_time REAL,
                end_time REAL,
                operator TEXT,
                client TEXT,
                target_network TEXT,
                classification TEXT,
                total_attacks INTEGER,
                success_rate REAL,
                chain_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chains (
                chain_id TEXT PRIMARY KEY,
                operation_id TEXT,
                timestamp REAL,
                target_type TEXT,
                target_vendor TEXT,
                num_attacks INTEGER,
                success INTEGER,
                duration REAL,
                chain_score REAL,
                FOREIGN KEY (operation_id) REFERENCES operations(operation_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT,
                attack_name TEXT,
                timestamp REAL,
                success INTEGER,
                execution_time REAL,
                score REAL,
                confidence REAL,
                mitre_id TEXT,
                tactic TEXT,
                technique_name TEXT,
                FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mitre_coverage (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT,
                tactic TEXT,
                usage_count INTEGER,
                avg_score REAL,
                last_used REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT,
                ioc_value TEXT,
                first_seen REAL,
                last_seen REAL,
                source_chain TEXT,
                description TEXT
            )
        ''')
        
        self.conn.commit()
    
    def add_operation(self, operation_id: str, operation_name: str, start_time: float,
                     end_time: Optional[float], operator: str, client: str,
                     target_network: str, classification: str) -> None:
        """Add operation to database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (operation_id, operation_name, start_time, end_time, operator,
              client, target_network, classification, 0, 0.0, 0.0))
        self.conn.commit()
    
    def add_chain(self, chain_id: str, operation_id: str, timestamp: float,
                  target_type: str, target_vendor: str, num_attacks: int,
                  success: bool, duration: float, chain_score: float) -> None:
        """Add attack chain to database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO chains VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chain_id, operation_id, timestamp, target_type, target_vendor,
              num_attacks, 1 if success else 0, duration, chain_score))
        self.conn.commit()
    
    def add_attack(self, chain_id: str, attack_name: str, timestamp: float,
                   success: bool, execution_time: float, score: float,
                   confidence: float, mitre_id: Optional[str],
                   tactic: Optional[str], technique_name: Optional[str]) -> None:
        """Add attack to database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO attacks (chain_id, attack_name, timestamp, success, execution_time,
                               score, confidence, mitre_id, tactic, technique_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chain_id, attack_name, timestamp, 1 if success else 0, execution_time,
              score, confidence, mitre_id, tactic, technique_name))
        self.conn.commit()
        
        if mitre_id:
            self._update_mitre_coverage(mitre_id, technique_name or attack_name,
                                       tactic or 'Unknown', timestamp, score)
    
    def _update_mitre_coverage(self, technique_id: str, technique_name: str,
                              tactic: str, timestamp: float, score: float) -> None:
        """Update MITRE technique coverage stats"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT usage_count, avg_score FROM mitre_coverage WHERE technique_id = ?',
                      (technique_id,))
        row = cursor.fetchone()
        
        if row:
            new_count = row[0] + 1
            new_avg = ((row[1] * row[0]) + score) / new_count
            cursor.execute('''
                UPDATE mitre_coverage SET usage_count = ?, avg_score = ?, last_used = ?
                WHERE technique_id = ?
            ''', (new_count, new_avg, timestamp, technique_id))
        else:
            cursor.execute('''
                INSERT INTO mitre_coverage VALUES (?, ?, ?, ?, ?, ?)
            ''', (technique_id, technique_name, tactic, 1, score, timestamp))
        
        self.conn.commit()
    
    def add_ioc(self, ioc_type: str, ioc_value: str, timestamp: float,
                source_chain: str, description: str = "") -> None:
        """Add Indicator of Compromise"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO iocs (ioc_type, ioc_value, first_seen, last_seen, source_chain, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ioc_type, ioc_value, timestamp, timestamp, source_chain, description))
        self.conn.commit()
    
    def close(self) -> None:
        """Close database connection"""
        self.conn.close()


class ElasticsearchExporter:
    """Export to Elasticsearch-compatible JSON"""
    
    @staticmethod
    def export_attack(attack: Dict[str, Any], index_name: str = "obscura-attacks") -> Dict[str, Any]:
        """Format attack for Elasticsearch"""
        return {
            '_index': index_name,
            '_type': '_doc',
            '_id': attack.get('attack_id', str(uuid.uuid4())),
            '_source': {
                '@timestamp': datetime.fromtimestamp(attack.get('timestamp', 0)).isoformat(),
                'attack': {
                    'name': attack.get('attack_name', ''),
                    'success': attack.get('success', False),
                    'score': attack.get('score', 0),
                    'confidence': attack.get('confidence', 0),
                    'execution_time_ms': attack.get('execution_time', 0) * 1000
                },
                'mitre': {
                    'technique_id': attack.get('mitre_id', ''),
                    'tactic': attack.get('tactic', ''),
                    'technique_name': attack.get('technique_name', '')
                },
                'target': {
                    'type': attack.get('target_type', ''),
                    'vendor': attack.get('target_vendor', ''),
                    'signal_strength': attack.get('signal_strength', -100)
                },
                'operation': {
                    'chain_id': attack.get('chain_id', ''),
                    'session_id': attack.get('session_id', ''),
                    'operator': attack.get('operator', '')
                }
            }
        }
    
    @staticmethod
    def export_batch(attacks: List[Dict[str, Any]], output_file: str,
                     index_name: str = "obscura-attacks") -> None:
        """Export batch for Elasticsearch bulk API"""
        with open(output_file, 'w') as f:
            for attack in attacks:
                doc = ElasticsearchExporter.export_attack(attack, index_name)
                
                action = {'index': {'_index': doc['_index'], '_id': doc['_id']}}
                f.write(json.dumps(action) + '\n')
                f.write(json.dumps(doc['_source']) + '\n')


class MISPExporter:
    """Export to MISP (Malware Information Sharing Platform) format"""
    
    def __init__(self, event_info: str, distribution: int = 0, threat_level: int = 2):
        self.event = {
            'Event': {
                'info': event_info,
                'distribution': distribution,
                'threat_level_id': threat_level,
                'analysis': 1,
                'date': datetime.now().strftime('%Y-%m-%d'),
                'Attribute': [],
                'Tag': []
            }
        }
    
    def add_attribute(self, attr_type: str, value: str, category: str,
                     comment: str = "", to_ids: bool = False) -> None:
        """Add attribute to MISP event"""
        self.event['Event']['Attribute'].append({
            'type': attr_type,
            'value': value,
            'category': category,
            'comment': comment,
            'to_ids': to_ids,
            'distribution': 0
        })
    
    def add_tag(self, name: str) -> None:
        """Add tag to MISP event"""
        self.event['Event']['Tag'].append({'name': name})
    
    def add_attack_pattern(self, technique_id: str, technique_name: str) -> None:
        """Add MITRE ATT&CK technique as attribute"""
        self.add_attribute(
            'text',
            f"{technique_id}: {technique_name}",
            'External analysis',
            f"MITRE ATT&CK technique used in operation",
            to_ids=False
        )
        
        self.add_tag(f'misp-galaxy:mitre-attack-pattern="{technique_name}"')
    
    def export(self, output_file: str) -> None:
        """Export to MISP JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.event, f, indent=2)


class IOCExtractor:
    """Extract Indicators of Compromise from attack data"""
    
    IPV4_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
    MAC_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    URL_PATTERN = re.compile(r'https?://(?:[a-zA-Z0-9$-_@.&+!*"(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    SSID_PATTERN = re.compile(r'(?:SSID|ssid)[:\s]+([^\s,;]{1,32})')
    BSSID_PATTERN = re.compile(r'(?:BSSID|bssid)[:\s]+([0-9a-fA-F:]{17})')
    
    def __init__(self):
        self.iocs: Dict[str, Set[str]] = {
            'ipv4': set(),
            'ipv6': set(),
            'mac': set(),
            'email': set(),
            'domain': set(),
            'url': set(),
            'md5': set(),
            'sha1': set(),
            'sha256': set(),
            'ssid': set(),
            'bssid': set(),
            'frequency': set(),
            'mitre_technique': set()
        }
    
    def extract_from_text(self, text: str) -> None:
        """Extract IOCs from text"""
        if not isinstance(text, str):
            text = str(text)
        
        self.iocs['ipv4'].update(self.IPV4_PATTERN.findall(text))
        self.iocs['ipv6'].update(self.IPV6_PATTERN.findall(text))
        self.iocs['mac'].update(self.MAC_PATTERN.findall(text))
        self.iocs['email'].update(self.EMAIL_PATTERN.findall(text))
        self.iocs['domain'].update(self.DOMAIN_PATTERN.findall(text))
        self.iocs['url'].update(self.URL_PATTERN.findall(text))
        self.iocs['md5'].update(self.MD5_PATTERN.findall(text))
        self.iocs['sha1'].update(self.SHA1_PATTERN.findall(text))
        self.iocs['sha256'].update(self.SHA256_PATTERN.findall(text))
        
        ssids = self.SSID_PATTERN.findall(text)
        if ssids:
            self.iocs['ssid'].update(ssids)
        
        bssids = self.BSSID_PATTERN.findall(text)
        if bssids:
            self.iocs['bssid'].update(bssids)
    
    def extract_from_dict(self, data: Dict[str, Any], source: str = "") -> None:
        """Extract IOCs from dictionary data"""
        for key, value in data.items():
            if isinstance(value, str):
                self.extract_from_text(value)
            elif isinstance(value, dict):
                self.extract_from_dict(value, f"{source}.{key}" if source else key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        self.extract_from_text(item)
                    elif isinstance(item, dict):
                        self.extract_from_dict(item, f"{source}.{key}" if source else key)
            
            if key.lower() in ['frequency', 'freq', 'channel']:
                try:
                    freq_str = str(value)
                    self.iocs['frequency'].add(freq_str)
                except:
                    pass
            
            if key.lower() in ['mitre_id', 'technique_id', 'mitre_technique']:
                if value:
                    self.iocs['mitre_technique'].add(str(value))
    
    def extract_from_chain(self, chain: Any) -> None:
        """Extract IOCs from attack chain"""
        if hasattr(chain, 'target_traits'):
            target_dict = {
                'device_type': chain.target_traits.device_type,
                'vendor': chain.target_traits.vendor,
                'services': chain.target_traits.services,
                'protocols': chain.target_traits.protocols,
                'location': chain.target_traits.location
            }
            self.extract_from_dict(target_dict)
        
        if hasattr(chain, 'scores'):
            for score in chain.scores:
                if hasattr(score, 'mitre_id') and score.mitre_id:
                    self.iocs['mitre_technique'].add(score.mitre_id)
                if hasattr(score, 'reason'):
                    self.extract_from_text(score.reason)
        
        if hasattr(chain, 'execution_log'):
            for log_entry in chain.execution_log:
                self.extract_from_dict(log_entry)
    
    def get_iocs(self) -> Dict[str, List[str]]:
        """Get all extracted IOCs as lists"""
        return {k: sorted(list(v)) for k, v in self.iocs.items() if v}
    
    def export_json(self, output_file: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Export IOCs to JSON"""
        ioc_report = {
            'timestamp': datetime.now().isoformat(),
            'ioc_count': sum(len(v) for v in self.iocs.values()),
            'metadata': metadata or {},
            'iocs': self.get_iocs()
        }
        
        with open(output_file, 'w') as f:
            json.dump(ioc_report, f, indent=2)
    
    def export_csv(self, output_file: str) -> None:
        """Export IOCs to CSV"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC Type', 'IOC Value', 'Timestamp'])
            
            timestamp = datetime.now().isoformat()
            for ioc_type, values in self.iocs.items():
                for value in sorted(values):
                    writer.writerow([ioc_type, value, timestamp])
    
    def export_stix(self, output_file: str, operation_name: str = "Obscura Operation") -> None:
        """Export IOCs as STIX indicators"""
        stix_exporter = STIXExporter(identity_name=operation_name)
        
        for ip in self.iocs['ipv4']:
            pattern = f"[network-traffic:src_ref.value = '{ip}' OR network-traffic:dst_ref.value = '{ip}']"
            stix_exporter.add_indicator(
                pattern, 
                'stix',
                f"IPv4 address observed during {operation_name}",
                ['network-activity']
            )
        
        for domain in self.iocs['domain']:
            pattern = f"[domain-name:value = '{domain}']"
            stix_exporter.add_indicator(
                pattern,
                'stix',
                f"Domain observed during {operation_name}",
                ['network-activity']
            )
        
        for url in self.iocs['url']:
            pattern = f"[url:value = '{url}']"
            stix_exporter.add_indicator(
                pattern,
                'stix',
                f"URL observed during {operation_name}",
                ['network-activity']
            )
        
        for file_hash in self.iocs['sha256']:
            pattern = f"[file:hashes.SHA256 = '{file_hash}']"
            stix_exporter.add_indicator(
                pattern,
                'stix',
                f"SHA256 hash observed during {operation_name}",
                ['malicious-activity']
            )
        
        stix_exporter.export(output_file)
    
    def export_misp(self, output_file: str, event_info: str = "Obscura Red Team IOCs") -> None:
        """Export IOCs to MISP format"""
        misp = MISPExporter(event_info)
        
        for ip in self.iocs['ipv4']:
            misp.add_attribute('ip-dst', ip, 'Network activity', 'IPv4 observed in operation', to_ids=True)
        
        for domain in self.iocs['domain']:
            misp.add_attribute('domain', domain, 'Network activity', 'Domain observed in operation', to_ids=True)
        
        for url in self.iocs['url']:
            misp.add_attribute('url', url, 'Network activity', 'URL observed in operation', to_ids=True)
        
        for mac in self.iocs['mac']:
            misp.add_attribute('mac-address', mac, 'Network activity', 'MAC address observed', to_ids=False)
        
        for sha256 in self.iocs['sha256']:
            misp.add_attribute('sha256', sha256, 'Artifacts dropped', 'File hash', to_ids=True)
        
        for technique in self.iocs['mitre_technique']:
            if technique:
                misp.add_tag(f'misp-galaxy:mitre-attack-pattern="{technique}"')
        
        misp.export(output_file)


def export_chain_all_formats(chain: Any, output_dir: str, operation_name: str = "Obscura Op") -> Dict[str, str]:
    """Export attack chain to all supported formats"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    exports = {}
    
    navigator = ATTACKNavigatorExporter(name=operation_name)
    for score in chain.scores:
        if score.mitre_id:
            navigator.add_technique(
                score.mitre_id,
                score.plugin_name,
                score.score,
                comment=score.reason
            )
    navigator_file = output_dir / f"attack_navigator_{timestamp}.json"
    navigator.export(str(navigator_file))
    exports['attack_navigator'] = str(navigator_file)
    
    attacks_data = []
    for i, attack in enumerate(chain.attacks):
        score_obj = next((s for s in chain.scores if s.plugin_name == attack), None)
        exec_log = next((log for log in chain.execution_log if log['attack'] == attack), None)
        
        attacks_data.append({
            'timestamp': exec_log['timestamp'] if exec_log else 0,
            'chain_id': chain.chain_id,
            'attack_name': attack,
            'success': exec_log['success'] if exec_log else False,
            'score': score_obj.score if score_obj else 0,
            'confidence': score_obj.confidence if score_obj else 0,
            'mitre_id': score_obj.mitre_id if score_obj else '',
            'execution_time': exec_log.get('execution_time', 0) if exec_log else 0,
            'target_type': chain.target_traits.device_type,
            'target_vendor': chain.target_traits.vendor or ''
        })
    
    csv_file = output_dir / f"attacks_{timestamp}.csv"
    CSVExporter.export_attacks(attacks_data, str(csv_file))
    exports['csv'] = str(csv_file)
    
    db_file = output_dir / f"operation_{timestamp}.db"
    db = SQLiteExporter(str(db_file))
    db.add_operation(
        chain.chain_id,
        operation_name,
        chain.start_time or 0,
        chain.end_time or 0,
        "operator",
        "client",
        chain.target_traits.device_type,
        "CONFIDENTIAL"
    )
    db.add_chain(
        chain.chain_id,
        chain.chain_id,
        chain.start_time or 0,
        chain.target_traits.device_type,
        chain.target_traits.vendor or '',
        len(chain.attacks),
        chain.success,
        (chain.end_time - chain.start_time) if chain.end_time and chain.start_time else 0,
        0.0
    )
    for attack_data in attacks_data:
        db.add_attack(
            chain.chain_id,
            attack_data['attack_name'],
            attack_data['timestamp'],
            attack_data['success'],
            attack_data['execution_time'],
            attack_data['score'],
            attack_data['confidence'],
            attack_data['mitre_id'],
            None,
            None
        )
    db.close()
    exports['sqlite'] = str(db_file)
    
    elk_file = output_dir / f"elasticsearch_{timestamp}.ndjson"
    ElasticsearchExporter.export_batch(attacks_data, str(elk_file))
    exports['elasticsearch'] = str(elk_file)
    
    return exports
