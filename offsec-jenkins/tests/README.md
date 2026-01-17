# offsec-jenkins Unit Tests

Comprehensive test suite for the Jenkins Credential Decryptor.

## Test Coverage

### test_decryption.py
- AES ECB decryption (old format)
- AES CBC decryption (new format)
- Confidentiality key derivation
- Base64 encoding/decoding
- Multiple test vectors
- Edge cases (invalid magic, bad padding, etc.)

### test_cli.py
- Command-line argument parsing
- Secret redaction functionality
- Sensitive credential detection
- Cross-platform path handling
- Directory recursive scanning

### test_export.py
- JSON export functionality
- CSV export functionality
- File overwrite protection (--force flag)
- Output directory creation
- Full CLI integration tests

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run specific test file
```bash
pytest tests/test_decryption.py
```

### Run with verbose output
```bash
pytest tests/ -v
```

### Run with coverage
```bash
pytest tests/ --cov=decrypt --cov-report=html
```

## Test Fixtures

Test fixtures are automatically generated using pytest fixtures defined in `conftest.py`:
- `test_fixtures_dir`: Temporary directory for test files
- `master_key_file`: Test master.key
- `hudson_secret_file`: Test hudson.util.Secret
- `credentials_xml_file`: Test credentials.xml with encrypted secrets
- `confidentiality_key`: Test AES key

## Jenkins Lab Testing

To test against actual Jenkins Lab credentials:

1. Start Jenkins Lab:
```bash
cd ~/jenkins-lab
docker-compose up -d
```

2. Extract Jenkins files:
```bash
docker cp jenkins-lab_jenkins_1:/var/jenkins_home/secrets/master.key ./test_fixtures/jenkins_lab/
docker cp jenkins-lab_jenkins_1:/var/jenkins_home/secrets/hudson.util.Secret ./test_fixtures/jenkins_lab/
docker cp jenkins-lab_jenkins_1:/var/jenkins_home/credentials.xml ./test_fixtures/jenkins_lab/
```

3. Run decryptor against Jenkins Lab:
```bash
python3 decrypt.py --path ./test_fixtures/jenkins_lab --export-json outputs/jenkins_lab_secrets.json --reveal-secrets
```

4. Validate results:
```bash
pytest tests/ --jenkins-lab
```

## Requirements

- pytest >= 7.4.0
- pycryptodome >= 3.20.0
