from flask import Flask, render_template, request, jsonify
import os
import sys
import threading
import requests
import webbrowser
from dotenv import load_dotenv

# Add parent directory to path for import resolution
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Lazy import wrapper for satnogsclient
satnogsclient = None

def get_satnogs_client():
    global satnogsclient
    if satnogsclient is None:
        import satnogsclient
    return satnogsclient

# Lazy import wrapper for satellite_attack
sat_attacks = None

def get_satellite_attacks():
    global sat_attacks
    if sat_attacks is None:
        try:
            from obscura.attack_plugins import satellite_attack
            sat_attacks = satellite_attack
        except Exception as e:
            print(f"[!] Could not import satellite_attack module: {e}")
            sat_attacks = None
    return sat_attacks

load_dotenv()
app = Flask(__name__, template_folder="templates")

# API Keys and constants
N2YO_API_KEY = os.getenv("N2YO_API_KEY")
SATNOGS_API = "https://db.satnogs.org/api/"

@app.route("/")
def index():
    return render_template("index.html", status="Ready")

@app.route("/satellites")
def get_satellites():
    try:
        response = requests.get("https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=TLE", timeout=5)
        lines = response.text.splitlines()
        satellites = [lines[i].strip() for i in range(0, len(lines), 3)]
        return jsonify(satellites[:100])
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/n2yo_position")
def n2yo_position():
    norad_id = request.args.get("id")
    if not N2YO_API_KEY:
        return jsonify({"error": "N2YO API key missing in environment variables."})
    try:
        url = f"https://api.n2yo.com/rest/v1/satellite/positions/{norad_id}/0/0/0/1/&apiKey={N2YO_API_KEY}"
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/satnogs_observations")
def satnogs_observations():
    norad_id = request.args.get("id")
    try:
        client = get_satnogs_client().SatNOGSClient()
        observations = client.get_observations(int(norad_id))
        return jsonify(observations)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/launch_attack", methods=["POST"])
def launch_attack():
    sat_name = request.json.get("satellite")
    module = get_satellite_attacks()
    if not module:
        return jsonify({"error": "satellite_attack module not available."})
    try:
        result = module.satellite_pass_spoof("/path/to/tle.txt", sat_name)
        return jsonify({"success": result})
    except Exception as e:
        return jsonify({"error": str(e)})

def run_server():
    print("\n[+] Satellite Dashboard running at http://127.0.0.1:5000\n")
    try:
        webbrowser.open("http://127.0.0.1:5000", new=2)
    except Exception as e:
        print(f"[!] Could not auto-launch browser: {e}")
    threading.Thread(target=lambda: app.run(debug=False, use_reloader=False)).start()
