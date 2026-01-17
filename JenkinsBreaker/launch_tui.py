#!/usr/bin/env python3
"""
JenkinsBreaker TUI Launcher - Production-Grade Terminal Interface
Launch with: python launch_tui.py --url http://localhost:8080 --username admin --password admin
"""

import sys
import argparse
from tui import JenkinsBreakerTUI

def main():
    parser = argparse.ArgumentParser(
        description="JenkinsBreaker TUI - Interactive Terminal Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launch_tui.py --url http://localhost:8080 --username admin --password admin
  python launch_tui.py --url http://jenkins.corp.com:8080
        """
    )
    
    parser.add_argument("--url", help="Jenkins URL (can be set in TUI)", default="")
    parser.add_argument("--username", help="Jenkins username (can be set in TUI)", default="")
    parser.add_argument("--password", help="Jenkins password (can be set in TUI)", default="")
    
    args = parser.parse_args()
    
    app = JenkinsBreakerTUI()
    
    if args.url:
        app.default_url = args.url
    if args.username:
        app.default_username = args.username
    if args.password:
        app.default_password = args.password
    
    app.run()

if __name__ == "__main__":
    main()
