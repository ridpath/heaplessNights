#!/usr/bin/env python3
"""
JenkinsBreaker Web UI Launcher - Production-Grade Browser Interface  
Launch with: python launch_webui.py
Access at: http://localhost:8000
"""

import uvicorn
import argparse
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="JenkinsBreaker Web UI - Browser-Based Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launch_webui.py
  python launch_webui.py --port 9000
  python launch_webui.py --host 0.0.0.0 --port 8000
        """
    )
    
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    
    args = parser.parse_args()
    
    console.print(f"[bold cyan]JenkinsBreaker Web UI Starting...[/bold cyan]")
    console.print(f"[green]Access the interface at: http://{args.host}:{args.port}[/green]")
    console.print(f"[yellow]Press CTRL+C to stop[/yellow]")
    console.print()
    
    uvicorn.run(
        "web_ui:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()
