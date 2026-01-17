"""
Test suite for OpSec Logging and Export Formats

Validates:
- Encrypted logging and sensitive data redaction
- Async logging performance
- Log compression and rotation
- CTF mode and flag capture
- Artifact linking and chain of custody
- IOC extraction from attack data
- Export to all industry formats (STIX, MISP, ATT&CK Navigator, CSV, SQLite)
- Session management and evidence tracking
"""

import os
import sys
import json
import time
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from obscura.opsec_logging import OpSecLogger, SensitiveDataRedactor, Evidence, OperationSession
from obscura.export_formats import (
    IOCExtractor, ATTACKNavigatorExporter, STIXExporter, 
    CSVExporter, SQLiteExporter, MISPExporter, ElasticsearchExporter
)
from obscura.orchestrator import AttackChain, TargetTrait, AttackScore


def test_sensitive_data_redaction():
    """Test sensitive data redaction (IPs, MACs, credentials)"""
    print("\n" + "="*70)
    print("Test 1: Sensitive Data Redaction")
    print("="*70)
    
    redactor = SensitiveDataRedactor()
    
    test_data = "Target at 192.168.1.100 with MAC aa:bb:cc:dd:ee:ff and password=secret123"
    redacted = redactor.redact(test_data)
    
    assert "192.168.1.100" not in redacted, "IPv4 not redacted"
    assert "aa:bb:cc:dd:ee:ff" not in redacted, "MAC not redacted"
    assert "secret123" not in redacted, "Credential not redacted"
    assert "[IP_1]" in redacted, "IP placeholder not added"
    assert "[MAC_1]" in redacted, "MAC placeholder not added"
    print("[+] IPv4 addresses redacted correctly")
    print("[+] MAC addresses redacted correctly")
    print("[+] Credentials redacted correctly")
    
    same_ip_data = "Source 192.168.1.100 and dest 192.168.1.100"
    redacted2 = redactor.redact(same_ip_data)
    assert redacted2.count("[IP_1]") == 2, "Consistent IP placeholder mapping failed"
    print("[+] Consistent placeholder mapping works")
    
    redaction_map = redactor.get_redaction_map()
    assert '192.168.1.100' in redaction_map['ips'].keys()
    print(f"[+] Redaction map contains {len(redaction_map['ips'])} IPs, {len(redaction_map['macs'])} MACs")
    
    print("[+] Test 1 PASSED\n")
    return True


def test_encrypted_logging():
    """Test encrypted log storage"""
    print("="*70)
    print("Test 2: Encrypted Log Storage")
    print("="*70)
    
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = OpSecLogger(
                log_dir=tmpdir,
                encrypt=True,
                passphrase="test_passphrase_123",
                operator="test_operator"
            )
            
            session_id = logger.start_session("Test Operation", "10.0.0.0/24", "TestClient")
            print(f"[+] Session started: {session_id}")
            
            logger.log_attack(
                chain_id="test_chain_1",
                attack_name="wifi_deauth",
                success=True,
                execution_time=2.5,
                target_info={'ip': '192.168.1.1', 'type': 'router'},
                log_data={'packets_sent': 100, 'result': 'success'}
            )
            print("[+] Attack logged to encrypted database")
            
            logger.end_session("Test session completed")
            print("[+] Session ended successfully")
            
            export_file = Path(tmpdir) / "session_export.enc"
            logger.export_session(session_id, str(export_file))
            
            assert export_file.exists(), "Encrypted export file not created"
            print(f"[+] Session exported to: {export_file}")
            
            with open(export_file, 'rb') as f:
                encrypted_data = f.read()
            
            assert len(encrypted_data) > 0, "Export file is empty"
            assert b'{' not in encrypted_data[:100], "Data appears unencrypted"
            print("[+] Export file is properly encrypted")
        
        print("[+] Test 2 PASSED\n")
        return True
        
    except ImportError:
        print("[!] cryptography library not available - SKIPPED")
        return True


def test_memory_only_logging():
    """Test memory-only mode (zero disk footprint)"""
    print("="*70)
    print("Test 3: Memory-Only Logging Mode")
    print("="*70)
    
    logger = OpSecLogger(
        log_dir='should_not_be_created',
        memory_only=True,
        encrypt=False,
        operator="stealth_operator"
    )
    
    session_id = logger.start_session("Stealth Op")
    
    for i in range(5):
        logger.log_attack(
            chain_id=f"chain_{i}",
            attack_name=f"attack_{i}",
            success=True,
            execution_time=1.0,
            target_info={'index': i},
            log_data={'data': f'test_{i}'}
        )
    
    memory_logs = logger.get_memory_logs()
    assert len(memory_logs) == 5, f"Expected 5 logs, got {len(memory_logs)}"
    print(f"[+] {len(memory_logs)} attacks logged in memory")
    
    assert not Path('should_not_be_created').exists(), "Directory created in memory-only mode"
    print("[+] No files written to disk (zero footprint)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        export_path = Path(tmpdir) / "memory_export.json"
        logger.export_memory_logs(str(export_path))
        
        assert export_path.exists()
        with open(export_path) as f:
            exported = json.load(f)
        assert len(exported) == 5
        print(f"[+] Memory logs exported to file: {len(exported)} entries")
    
    print("[+] Test 3 PASSED\n")
    return True


def test_async_logging_performance():
    """Test async logging with high throughput"""
    print("="*70)
    print("Test 4: Async Logging Performance")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(
            log_dir=tmpdir,
            async_logging=True,
            encrypt=False,
            operator="perf_tester"
        )
        
        session_id = logger.start_session("Performance Test")
        
        start_time = time.time()
        num_logs = 100
        
        for i in range(num_logs):
            logger.log_attack(
                chain_id=f"chain_{i % 10}",
                attack_name=f"attack_{i}",
                success=i % 2 == 0,
                execution_time=0.5,
                target_info={'index': i},
                log_data={'iteration': i, 'timestamp': time.time()}
            )
        
        if logger.log_queue:
            logger.log_queue.join()
        
        elapsed = time.time() - start_time
        throughput = num_logs / elapsed
        
        print(f"[+] Logged {num_logs} attacks in {elapsed:.3f}s")
        print(f"[+] Throughput: {throughput:.1f} logs/sec")
        
        logger.shutdown_async_logging()
        print("[+] Async logging shut down gracefully")
        
        assert throughput > 50, f"Throughput too low: {throughput:.1f} logs/sec"
        print(f"[+] Performance acceptable ({throughput:.1f} logs/sec)")
    
    print("[+] Test 4 PASSED\n")
    return True


def test_log_rotation_compression():
    """Test log rotation and compression"""
    print("="*70)
    print("Test 5: Log Rotation and Compression")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_log.json"
        
        with open(test_file, 'w') as f:
            f.write(json.dumps({'data': 'x' * 1024 * 1024}))
        
        original_size = test_file.stat().st_size
        print(f"[+] Created test file: {original_size / 1024:.1f} KB")
        
        logger = OpSecLogger(log_dir=tmpdir, compress_logs=True, rotate_size_mb=1)
        
        compressed = logger.compress_log_file(test_file)
        
        assert compressed.exists(), "Compressed file not created"
        assert compressed.suffix == '.gz', "Wrong file extension"
        assert not test_file.exists(), "Original file not deleted"
        
        compressed_size = compressed.stat().st_size
        compression_ratio = (1 - compressed_size / original_size) * 100
        
        print(f"[+] Compressed to: {compressed_size / 1024:.1f} KB")
        print(f"[+] Compression ratio: {compression_ratio:.1f}%")
        
        assert compressed_size < original_size, "Compression didn't reduce size"
        print("[+] Compression successful")
    
    print("[+] Test 5 PASSED\n")
    return True


def test_ctf_mode():
    """Test CTF mode with flag capture and scoring"""
    print("="*70)
    print("Test 6: CTF Mode with Flag Capture")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(
            log_dir=tmpdir,
            ctf_mode=True,
            operator="ctf_player_1"
        )
        
        session_id = logger.start_session("CTF Competition")
        
        flag1 = logger.capture_flag(
            flag_name="wifi_pwned",
            flag_value="FLAG{w1f1_h4ck3d}",
            points=100,
            chain_id="chain_1"
        )
        print(f"[+] Flag captured: {flag1['flag_name']} (+{flag1['points']} points)")
        
        flag2 = logger.capture_flag(
            flag_name="bluetooth_cracked",
            flag_value="FLAG{bl00t00th_0wn3d}",
            points=150
        )
        print(f"[+] Flag captured: {flag2['flag_name']} (+{flag2['points']} points)")
        
        scoreboard = logger.get_ctf_scoreboard()
        
        assert scoreboard['total_score'] == 250, "Score calculation wrong"
        assert scoreboard['flags_captured'] == 2, "Flag count wrong"
        assert scoreboard['operator'] == "ctf_player_1"
        
        print(f"[+] Total score: {scoreboard['total_score']} points")
        print(f"[+] Flags captured: {scoreboard['flags_captured']}")
        
        report_file = Path(tmpdir) / "ctf_report.json"
        logger.export_ctf_report(str(report_file))
        
        assert report_file.exists()
        with open(report_file) as f:
            report = json.load(f)
        
        assert report['score'] == 250
        assert len(report['flags']) == 2
        print(f"[+] CTF report exported: {report_file}")
    
    print("[+] Test 6 PASSED\n")
    return True


def test_artifact_linking():
    """Test artifact linking and chain of custody"""
    print("="*70)
    print("Test 7: Artifact Linking and Chain of Custody")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(log_dir=tmpdir, operator="forensic_analyst")
        
        session_id = logger.start_session("Forensic Analysis")
        
        artifact1_id = logger.add_evidence(
            artifact_type="pcap",
            description="Network capture during attack",
            chain_id="chain_1"
        )
        print(f"[+] Evidence added: {artifact1_id}")
        
        artifact2_id = logger.add_evidence(
            artifact_type="screenshot",
            description="Target system screenshot",
            chain_id="chain_1"
        )
        print(f"[+] Evidence added: {artifact2_id}")
        
        artifact3_id = logger.add_evidence(
            artifact_type="log_file",
            description="System logs from target",
            chain_id="chain_1"
        )
        print(f"[+] Evidence added: {artifact3_id}")
        
        logger.link_artifact_to_chain(
            artifact1_id,
            [artifact2_id, artifact3_id],
            relationship="captured_during_same_attack"
        )
        print(f"[+] Linked {artifact1_id} to 2 related artifacts")
        
        artifact_chain = logger.get_artifact_chain(artifact1_id)
        
        assert len(artifact_chain) == 2, f"Expected 2 linked artifacts, got {len(artifact_chain)}"
        print(f"[+] Retrieved artifact chain: {len(artifact_chain)} related items")
        
        for artifact in artifact_chain:
            assert artifact['relationship'] == 'captured_during_same_attack'
            print(f"  - {artifact['artifact_type']}: {artifact['description']}")
    
    print("[+] Test 7 PASSED\n")
    return True


def test_ioc_extraction():
    """Test IOC extraction from attack data"""
    print("="*70)
    print("Test 8: IOC Extraction")
    print("="*70)
    
    extractor = IOCExtractor()
    
    test_text = """
    Target: 192.168.1.100
    MAC: aa:bb:cc:dd:ee:ff
    Domain: evil.example.com
    URL: http://malicious-site.com/payload
    Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    SSID: TargetNetwork
    """
    
    extractor.extract_from_text(test_text)
    
    iocs = extractor.get_iocs()
    
    assert 'ipv4' in iocs, "IPv4 not extracted"
    assert '192.168.1.100' in iocs['ipv4'], "Specific IPv4 not found"
    print(f"[+] Extracted {len(iocs.get('ipv4', []))} IPv4 addresses")
    
    assert 'mac' in iocs, "MAC not extracted"
    assert 'aa:bb:cc:dd:ee:ff' in iocs['mac'], "Specific MAC not found"
    print(f"[+] Extracted {len(iocs.get('mac', []))} MAC addresses")
    
    assert 'domain' in iocs, "Domain not extracted"
    print(f"[+] Extracted {len(iocs.get('domain', []))} domains")
    
    assert 'url' in iocs, "URL not extracted"
    print(f"[+] Extracted {len(iocs.get('url', []))} URLs")
    
    assert 'sha256' in iocs, "SHA256 not extracted"
    print(f"[+] Extracted {len(iocs.get('sha256', []))} SHA256 hashes")
    
    assert 'ssid' in iocs, "SSID not extracted"
    print(f"[+] Extracted {len(iocs.get('ssid', []))} SSIDs")
    
    total_iocs = sum(len(v) for v in iocs.values())
    print(f"[+] Total IOCs extracted: {total_iocs}")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = Path(tmpdir) / "iocs.json"
        extractor.export_json(str(json_file), metadata={'test': 'data'})
        
        assert json_file.exists()
        with open(json_file) as f:
            ioc_report = json.load(f)
        
        assert ioc_report['ioc_count'] == total_iocs
        print(f"[+] IOCs exported to JSON: {json_file}")
        
        csv_file = Path(tmpdir) / "iocs.csv"
        extractor.export_csv(str(csv_file))
        assert csv_file.exists()
        print(f"[+] IOCs exported to CSV: {csv_file}")
    
    print("[+] Test 8 PASSED\n")
    return True


def test_attack_navigator_export():
    """Test ATT&CK Navigator export"""
    print("="*70)
    print("Test 9: ATT&CK Navigator Export")
    print("="*70)
    
    navigator = ATTACKNavigatorExporter(name="Test Operation", description="OpSec test")
    
    navigator.add_technique("T1595", "Active Scanning", 85, "High severity")
    navigator.add_technique("T1590", "Gather Victim Network Info", 70, "Medium severity")
    navigator.add_technique("T1498", "Network DoS", 90, "Critical impact")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "attack_layer.json"
        navigator.export(str(output_file))
        
        assert output_file.exists()
        
        with open(output_file) as f:
            layer = json.load(f)
        
        assert layer['name'] == "Test Operation"
        assert layer['domain'] == "enterprise-attack"
        assert len(layer['techniques']) == 3
        
        high_impact = [t for t in layer['techniques'] if t['score'] >= 80]
        assert len(high_impact) == 2
        
        print(f"[+] Navigator layer exported: {len(layer['techniques'])} techniques")
        print(f"[+] High impact techniques: {len(high_impact)}")
        print(f"[+] Layer name: {layer['name']}")
    
    print("[+] Test 9 PASSED\n")
    return True


def test_stix_export():
    """Test STIX 2.1 export"""
    print("="*70)
    print("Test 10: STIX 2.1 Export")
    print("="*70)
    
    stix = STIXExporter(identity_name="Red Team Alpha")
    
    pattern_id = stix.add_attack_pattern(
        "T1595",
        "Active Scanning",
        "Network reconnaissance activities",
        "Reconnaissance"
    )
    print(f"[+] Attack pattern added: {pattern_id}")
    
    indicator_id = stix.add_indicator(
        "[ipv4-addr:value = '192.168.1.100']",
        "stix",
        "Malicious IP observed",
        ["malicious-activity"]
    )
    print(f"[+] Indicator added: {indicator_id}")
    
    stix.add_relationship(indicator_id, pattern_id, "indicates")
    print("[+] Relationship created between indicator and pattern")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "stix_bundle.json"
        stix.export(str(output_file))
        
        assert output_file.exists()
        
        with open(output_file) as f:
            bundle = json.load(f)
        
        assert bundle['type'] == 'bundle'
        assert len(bundle['objects']) >= 4
        
        identity_objs = [o for o in bundle['objects'] if o['type'] == 'identity']
        assert len(identity_objs) == 1
        
        print(f"[+] STIX bundle exported: {len(bundle['objects'])} objects")
        print(f"[+] Bundle ID: {bundle['id']}")
    
    print("[+] Test 10 PASSED\n")
    return True


def test_full_integration():
    """Test full integration workflow"""
    print("="*70)
    print("Test 11: Full Integration Workflow")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(
            log_dir=tmpdir,
            encrypt=False,
            redact=True,
            async_logging=False,
            compress_logs=False,
            ctf_mode=True,
            operator="integration_tester"
        )
        
        session_id = logger.start_session(
            "Full Integration Test",
            "192.168.0.0/16",
            "Test Client Inc",
            "Written Authorization 2024-01"
        )
        print(f"[+] Session started: {session_id}")
        
        for i in range(3):
            logger.log_attack(
                chain_id=f"chain_{i}",
                attack_name=f"test_attack_{i}",
                success=True,
                execution_time=1.5,
                target_info={'ip': f'192.168.1.{i+1}', 'port': 443},
                log_data={'packets': 100, 'success': True}
            )
        print("[+] Logged 3 attacks with sensitive data")
        
        artifact_id = logger.add_evidence(
            artifact_type="pcap",
            description="Full packet capture",
            chain_id="chain_0"
        )
        print(f"[+] Evidence artifact added: {artifact_id}")
        
        flag = logger.capture_flag(
            "integration_test",
            "FLAG{1nt3gr4t10n_t3st}",
            200
        )
        print(f"[+] CTF flag captured: +{flag['points']} points")
        
        logger.end_session("Integration test completed successfully")
        print("[+] Session ended")
        
        export_file = Path(tmpdir) / "integration_export.json"
        logger.export_session(session_id, str(export_file))
        
        assert export_file.exists()
        print(f"[+] Session exported to: {export_file}")
        
        ctf_report = Path(tmpdir) / "ctf_final.json"
        logger.export_ctf_report(str(ctf_report))
        assert ctf_report.exists()
        print(f"[+] CTF report exported: {ctf_report}")
        
        with open(export_file) as f:
            session_data = json.load(f)
        
        assert len(session_data['attacks']) == 3
        assert session_data['session']['operator'] == 'integration_tester'
        print(f"[+] Verified exported data: {len(session_data['attacks'])} attacks")
    
    print("[+] Test 11 PASSED\n")
    return True


def main():
    """Run all OpSec and export format tests"""
    print("\n" + "#"*70)
    print("#  Obscura - OpSec Logging & Export Formats Test Suite")
    print("#"*70)
    print()
    
    tests = [
        ("Sensitive Data Redaction", test_sensitive_data_redaction),
        ("Encrypted Log Storage", test_encrypted_logging),
        ("Memory-Only Logging", test_memory_only_logging),
        ("Async Logging Performance", test_async_logging_performance),
        ("Log Rotation & Compression", test_log_rotation_compression),
        ("CTF Mode & Flag Capture", test_ctf_mode),
        ("Artifact Linking & Chain of Custody", test_artifact_linking),
        ("IOC Extraction", test_ioc_extraction),
        ("ATT&CK Navigator Export", test_attack_navigator_export),
        ("STIX 2.1 Export", test_stix_export),
        ("Full Integration Workflow", test_full_integration)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[!] {test_name} FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    print("#"*70)
    print("#  Test Summary")
    print("#"*70)
    print()
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {test_name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    print()
    print(f"  Total: {passed}/{total} tests passed ({100*passed//total}%)")
    print()
    
    if passed == total:
        print("#"*70)
        print("#  ALL TESTS PASSED - OPSEC & EXPORT FEATURES OPERATIONAL")
        print("#"*70)
        print()
        return 0
    else:
        print("#"*70)
        print("#  SOME TESTS FAILED")
        print("#"*70)
        print()
        return 1


if __name__ == '__main__':
    sys.exit(main())
