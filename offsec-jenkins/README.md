# 🔐 Jenkins Credential Decryptor

This Python script is a post-exploitation utility designed for penetration testers and red team operators to decrypt stored Jenkins credentials **offline**. It recovers plaintext secrets from Jenkins `credentials.xml` using the `master.key` and `hudson.util.Secret` files.

---

## 🚀 Use Case

When Jenkins is compromised, attackers can access the following:

- `secrets/master.key`
- `secrets/hudson.util.Secret`
- `credentials.xml` (in user directories or global config)

This script decrypts those credential entries, including:

- API tokens  
- SSH keys  
- Stored passwords

---

## 🔎 Features

- 🔁 Automatically sets up a local Python virtual environment  
- 🧠 Supports both old (ECB) and new (CBC) AES encryption formats  
- 💬 Interactive mode for manual decryption  
- 📂 Batch decryption of full `credentials.xml` files  
- 🧼 Handles base64 decoding and PKCS#7 unpadding  

---

## 📦 Dependencies

- Python 3.6+  
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) *(auto-installed inside a `.venv`)*

---

## 🛠️ Example Usage

```bash
python3 decrypt.py /var/lib/jenkins/
# OR
python3 decrypt.py master.key hudson.util.Secret credentials.xml
# OR interactive mode
python3 decrypt.py -i /var/lib/jenkins/

📁 Typical Jenkins Paths
File	Path
master.key	/var/lib/jenkins/secrets/master.key
hudson.util.Secret	/var/lib/jenkins/secrets/hudson.util.Secret
credentials.xml	/var/lib/jenkins/credentials.xml

🧠 Pentesting Context
This tool is ideal for red team post-exploitation during:

CI/CD pipeline credential extraction

Lateral movement via build infrastructure

Reconnaissance on DevOps/infra assets

Token harvesting (e.g., AWS, GitHub, cloud APIs)

⚠️ Legal Notice
Use only on systems you have explicit permission to test.
This tool is for educational and authorized security assessments only.

🙏 Attribution
Portions of the decryption logic are based on the excellent research and code from
gquere/pwn_jenkins.
This version has been significantly adapted and extended for modern post-exploitation workflows.
