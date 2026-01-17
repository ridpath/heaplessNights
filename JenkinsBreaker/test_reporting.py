"""
Test script for JenkinsBreaker Reporting System
"""

import sys
import os
from reporting import ReportManager

def test_basic_reporting():
    """Test basic reporting functionality."""
    print("[*] Testing JenkinsBreaker Reporting System...")
    
    manager = ReportManager(base_dir="test_reports")
    
    print("[+] Step 1: Setting target info...")
    manager.set_target_info(
        url="http://test-jenkins:8080",
        version="2.440",
        plugins=["git", "github", "workflow-aggregator"],
        vulnerabilities=["CVE-2024-23897", "CVE-2019-1003029"]
    )
    
    print("[+] Step 2: Logging test exploits...")
    
    manager.log_exploit(
        exploit_name="Jenkins CLI Arbitrary File Read",
        cve_id="CVE-2024-23897",
        status="success",
        details="Successfully read /etc/passwd via CLI @file syntax",
        mitre_ids=["T1190", "T1552.001"],
        data={"file_read": "/etc/passwd", "bytes_read": 1234}
    )
    
    manager.log_exploit(
        exploit_name="Groovy RCE via checkScript",
        cve_id="CVE-2019-1003029",
        status="success",
        details="Successfully executed Groovy payload",
        mitre_ids=["T1190", "T1059", "T1059.007"],
        data={"payload": "def cmd = 'whoami'.execute()"}
    )
    
    manager.log_exploit(
        exploit_name="Script Security Sandbox Bypass",
        cve_id="CVE-2023-24422",
        status="failed",
        details="Target not vulnerable or patched",
        mitre_ids=["T1059", "T1190"],
        data={}
    )
    
    manager.log_exploit(
        exploit_name="Agent-to-Controller Path Traversal",
        cve_id="CVE-2021-21686",
        status="error",
        details="Connection timeout",
        mitre_ids=["T1083", "T1552.001", "T1005"],
        data={}
    )
    
    print("[+] Step 3: Generating reports...")
    
    json_file = manager.generate_json_report()
    print(f"[+] JSON report: {json_file}")
    
    md_file = manager.generate_markdown_report()
    print(f"[+] Markdown report: {md_file}")
    
    mitre_md = manager.generate_mitre_matrix()
    print(f"[+] MITRE ATT&CK matrix generated")
    
    print("[+] Step 4: Generating PDF report...")
    pdf_file = manager.generate_pdf_report()
    if pdf_file:
        print(f"[+] PDF report: {pdf_file}")
    else:
        print("[!] PDF generation skipped (WeasyPrint not available)")
    
    print("[+] Step 5: Generating all reports at once...")
    results = manager.generate_all_reports(['json', 'md', 'mitre'])
    print(f"[+] Generated {len(results)} report types")
    
    print("\n[+] Step 6: Summary...")
    manager.print_summary()
    
    print("\n[+] All tests passed!")
    print(f"[+] Reports saved to: {manager.session_dir}")
    
    return True

if __name__ == "__main__":
    try:
        success = test_basic_reporting()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[!] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
