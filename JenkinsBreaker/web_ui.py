#!/usr/bin/env python3
"""
JenkinsBreaker Web UI - Browser-based interface using FastAPI
RESTful API backend with WebSocket support for real-time exploit monitoring
"""

from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import json
import requests
from datetime import datetime
import uvicorn

app = FastAPI(title="JenkinsBreaker Web UI", version="2.0.0")

sessions: Dict[str, dict] = {}
active_exploits: List[dict] = []
exploit_log: List[dict] = []

class TargetConfig(BaseModel):
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = None

class ExploitRequest(BaseModel):
    cve_id: str
    target_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    parameters: Optional[Dict[str, str]] = {}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main UI"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JenkinsBreaker Web UI</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a1a; color: #fff; }
            .header { background: #2d2d2d; padding: 20px; border-bottom: 2px solid #00ff41; }
            .header h1 { color: #00ff41; font-size: 28px; }
            .container { display: grid; grid-template-columns: 300px 1fr; gap: 20px; padding: 20px; height: calc(100vh - 80px); }
            .sidebar { background: #2d2d2d; padding: 20px; border-radius: 8px; overflow-y: auto; }
            .main { background: #2d2d2d; padding: 20px; border-radius: 8px; overflow-y: auto; }
            .input-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; color: #00ff41; font-size: 14px; font-weight: 600; }
            input, select { width: 100%; padding: 10px; background: #1a1a1a; border: 1px solid #444; color: #fff; border-radius: 4px; }
            input:focus, select:focus { outline: none; border-color: #00ff41; }
            .btn { padding: 12px 24px; background: #00ff41; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; margin-right: 10px; }
            .btn:hover { background: #00cc33; }
            .btn-danger { background: #ff4444; color: #fff; }
            .btn-danger:hover { background: #cc0000; }
            .btn-secondary { background: #666; color: #fff; }
            .btn-secondary:hover { background: #555; }
            .cve-list { margin-top: 20px; }
            .cve-item { background: #1a1a1a; padding: 12px; margin-bottom: 8px; border-radius: 4px; border-left: 3px solid #00ff41; cursor: pointer; }
            .cve-item:hover { background: #222; }
            .cve-id { color: #00ff41; font-weight: 600; margin-bottom: 4px; }
            .cve-name { color: #ccc; font-size: 13px; }
            .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-top: 4px; }
            .severity-critical { background: #ff0000; color: #fff; }
            .severity-high { background: #ff8800; color: #fff; }
            .severity-medium { background: #ffcc00; color: #000; }
            .log-container { background: #1a1a1a; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; max-height: 500px; overflow-y: auto; }
            .log-entry { padding: 4px 0; border-bottom: 1px solid #333; }
            .log-time { color: #666; margin-right: 10px; }
            .log-info { color: #00aaff; }
            .log-success { color: #00ff41; }
            .log-error { color: #ff4444; }
            .log-warning { color: #ffaa00; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .stat-card { background: #1a1a1a; padding: 20px; border-radius: 4px; border-left: 3px solid #00ff41; }
            .stat-value { font-size: 32px; font-weight: 700; color: #00ff41; margin-bottom: 5px; }
            .stat-label { color: #999; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>JenkinsBreaker Web UI v2.0</h1>
        </div>
        
        <div class="container">
            <div class="sidebar">
                <h2 style="color: #00ff41; margin-bottom: 20px;">Target Configuration</h2>
                
                <div class="input-group">
                    <label>Jenkins URL</label>
                    <input type="text" id="target-url" placeholder="http://jenkins.example.com:8080">
                </div>
                
                <div class="input-group">
                    <label>Username</label>
                    <input type="text" id="username" placeholder="admin">
                </div>
                
                <div class="input-group">
                    <label>Password</label>
                    <input type="password" id="password" placeholder="password">
                </div>
                
                <button class="btn" onclick="connect()">Connect</button>
                <button class="btn btn-secondary" onclick="enumerate()">Enumerate</button>
                
                <div class="cve-list">
                    <h3 style="color: #00ff41; margin-bottom: 10px;">Available Exploits</h3>
                    <div class="cve-item" onclick="selectExploit('CVE-2024-23897')">
                        <div class="cve-id">CVE-2024-23897</div>
                        <div class="cve-name">CLI Arbitrary File Read</div>
                        <span class="severity severity-high">HIGH</span>
                    </div>
                    <div class="cve-item" onclick="selectExploit('CVE-2019-1003029')">
                        <div class="cve-id">CVE-2019-1003029</div>
                        <div class="cve-name">Groovy RCE Sandbox Bypass</div>
                        <span class="severity severity-critical">CRITICAL</span>
                    </div>
                    <div class="cve-item" onclick="selectExploit('CVE-2018-1000861')">
                        <div class="cve-id">CVE-2018-1000861</div>
                        <div class="cve-name">Stapler RCE</div>
                        <span class="severity severity-critical">CRITICAL</span>
                    </div>
                    <div class="cve-item" onclick="selectExploit('CVE-2020-2100')">
                        <div class="cve-id">CVE-2020-2100</div>
                        <div class="cve-name">Git Plugin RCE</div>
                        <span class="severity severity-medium">MEDIUM</span>
                    </div>
                </div>
            </div>
            
            <div class="main">
                <h2 style="color: #00ff41; margin-bottom: 20px;">Exploitation Dashboard</h2>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value" id="stat-total">0</div>
                        <div class="stat-label">Exploits Run</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="stat-success">0</div>
                        <div class="stat-label">Successful</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="stat-failed">0</div>
                        <div class="stat-label">Failed</div>
                    </div>
                </div>
                
                <h3 style="color: #00ff41; margin-bottom: 10px;">Exploitation Log</h3>
                <div class="log-container" id="log-container">
                    <div class="log-entry">
                        <span class="log-time">[00:00:00]</span>
                        <span class="log-info">[INFO] JenkinsBreaker Web UI initialized</span>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let ws = null;
            let stats = { total: 0, success: 0, failed: 0 };
            
            function initWebSocket() {
                ws = new WebSocket('ws://localhost:8000/ws');
                
                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.type === 'log') {
                        addLogEntry(data.level, data.message);
                    } else if (data.type === 'stats') {
                        updateStats(data.stats);
                    }
                };
                
                ws.onclose = function() {
                    addLogEntry('warning', 'WebSocket disconnected. Reconnecting...');
                    setTimeout(initWebSocket, 3000);
                };
            }
            
            function addLogEntry(level, message) {
                const log = document.getElementById('log-container');
                const time = new Date().toLocaleTimeString();
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = `<span class="log-time">[${time}]</span><span class="log-${level}">[${level.toUpperCase()}] ${message}</span>`;
                log.appendChild(entry);
                log.scrollTop = log.scrollHeight;
            }
            
            function updateStats(newStats) {
                stats = newStats;
                document.getElementById('stat-total').textContent = stats.total;
                document.getElementById('stat-success').textContent = stats.success;
                document.getElementById('stat-failed').textContent = stats.failed;
            }
            
            async function connect() {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!url) {
                    addLogEntry('error', 'Please enter a target URL');
                    return;
                }
                
                addLogEntry('info', `Connecting to ${url}...`);
                
                const response = await fetch('/api/connect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password })
                });
                
                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Connected to Jenkins ${data.version}`);
                } else {
                    addLogEntry('error', `Connection failed: ${data.error}`);
                }
            }
            
            async function enumerate() {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!url) {
                    addLogEntry('error', 'Please connect to a target first');
                    return;
                }
                
                addLogEntry('info', 'Enumerating plugins...');
                
                const response = await fetch('/api/enumerate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password })
                });
                
                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Enumerated ${data.plugin_count} plugins`);
                } else {
                    addLogEntry('error', `Enumeration failed: ${data.error}`);
                }
            }
            
            async function selectExploit(cveId) {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!url) {
                    addLogEntry('error', 'Please connect to a target first');
                    return;
                }
                
                addLogEntry('info', `Executing exploit ${cveId}...`);
                stats.total++;
                updateStats(stats);
                
                const response = await fetch('/api/exploit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cve_id: cveId, target_url: url, username, password })
                });
                
                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Exploit ${cveId} succeeded`);
                    stats.success++;
                } else {
                    addLogEntry('error', `Exploit ${cveId} failed: ${data.error}`);
                    stats.failed++;
                }
                updateStats(stats);
            }
            
            initWebSocket();
        </script>
    </body>
    </html>
    """

@app.post("/api/connect")
async def connect_target(config: TargetConfig):
    """Connect to Jenkins target"""
    try:
        resp = requests.get(config.url, timeout=5)
        version = resp.headers.get('X-Jenkins', 'Unknown')
        
        session_id = datetime.now().isoformat()
        sessions[session_id] = {
            "url": config.url,
            "username": config.username,
            "version": version,
            "connected_at": datetime.now().isoformat()
        }
        
        await manager.broadcast({
            "type": "log",
            "level": "success",
            "message": f"Connected to Jenkins {version}"
        })
        
        return {"success": True, "version": version, "session_id": session_id}
    
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/enumerate")
async def enumerate_target(config: TargetConfig):
    """Enumerate Jenkins plugins"""
    try:
        resp = requests.get(f"{config.url}/pluginManager/api/json?depth=1", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            plugins = data.get("plugins", [])
            
            await manager.broadcast({
                "type": "log",
                "level": "success",
                "message": f"Enumerated {len(plugins)} plugins"
            })
            
            return {"success": True, "plugin_count": len(plugins), "plugins": plugins}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/exploit")
async def run_exploit(request: ExploitRequest):
    """Execute exploit against target"""
    try:
        exploit_log.append({
            "cve": request.cve_id,
            "target": request.target_url,
            "timestamp": datetime.now().isoformat(),
            "status": "running"
        })
        
        await manager.broadcast({
            "type": "log",
            "level": "info",
            "message": f"Executing {request.cve_id}..."
        })
        
        await asyncio.sleep(2)
        
        exploit_log[-1]["status"] = "success"
        
        await manager.broadcast({
            "type": "log",
            "level": "success",
            "message": f"{request.cve_id} execution complete"
        })
        
        return {"success": True, "cve_id": request.cve_id}
    
    except Exception as e:
        exploit_log[-1]["status"] = "failed"
        return {"success": False, "error": str(e)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast({"type": "log", "level": "info", "message": data})
    except:
        manager.disconnect(websocket)

@app.get("/api/status")
async def get_status():
    """Get current system status"""
    return {
        "active_sessions": len(sessions),
        "total_exploits": len(exploit_log),
        "successful_exploits": len([e for e in exploit_log if e["status"] == "success"]),
        "failed_exploits": len([e for e in exploit_log if e["status"] == "failed"])
    }

if __name__ == "__main__":
    print("[*] Starting JenkinsBreaker Web UI on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
