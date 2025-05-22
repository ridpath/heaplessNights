# api.py
from flask import Flask, request, jsonify
from .attacks import AttackOrchestrator
from .utils import log_message, INTERFACE

app = Flask(__name__)
orchestrator = AttackOrchestrator(INTERFACE)

@app.route('/start_jamming', methods=['POST'])
def start_jamming():
    data = request.json
    vector = data.get('vector')
    args = data.get('args', [])
    if vector in orchestrator.attack_vectors:
        result = orchestrator.execute(vector, *args)
        return jsonify({"status": "success" if result else "failure"})
    return jsonify({"status": "invalid_vector"}), 400

@app.route('/stop_jamming', methods=['POST'])
def stop_jamming():
    global HACKRF_PROCESS, ACTIVE_PROCESSES
    for proc in ACTIVE_PROCESSES:
        if proc.poll() is None:
            proc.terminate()
    if HACKRF_PROCESS:
        HACKRF_PROCESS.terminate()
        HACKRF_PROCESS = None
    return jsonify({"status": "stopped"})

@app.route('/scan_vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    data = request.json
    camera_mac = data.get('camera_mac')
    vulnerabilities = orchestrator.scan_vulnerabilities(camera_mac, None)
    return jsonify({"vulnerabilities": vulnerabilities})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)  #updated to not conflict with satellite_ui.py
