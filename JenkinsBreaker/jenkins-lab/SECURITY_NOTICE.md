# SECURITY NOTICE - TEST ENVIRONMENT ONLY

## Intentional Secrets for Security Testing

This Jenkins Lab environment contains **INTENTIONALLY FAKE CREDENTIALS** for authorized security testing and research.

### Purpose
- Red team training and certification
- CVE vulnerability validation
- CI/CD security research
- Penetration testing practice

### Fake Credentials Included
All API keys, tokens, and credentials in this directory are:
- **NOT REAL** - Generated for testing only
- **NOT ACTIVE** - Will not work with actual services
- **SAFE TO COMMIT** - Part of vulnerable test environment

### Files with Test Secrets
- `init.groovy.d/03-configure-credentials.groovy`
- `jobs/*/config.xml`
- `secrets/*.env`

### GitHub Secret Scanning
If GitHub push protection blocks these files:
1. Use the provided GitHub URLs to allowlist each secret
2. Confirm they are test credentials for security research
3. These secrets are documented and intentional

### Usage Authorization
This environment must only be used in:
- Isolated lab environments
- Authorized penetration tests
- Educational/research settings
- CTF competitions

**DO NOT USE IN PRODUCTION**

---

For questions about this test environment, see:
- `jenkins-lab/README.md`
- `../SECRETS_EXTRACTION_GUIDE.md`
- Repository root `README.md`
