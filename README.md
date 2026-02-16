# Node.js Security Tools

Web security analysis tools built with Node.js.

## Tools

| Tool | Description |
|------|-------------|
| `header-checker.js` | HTTP security header analyzer |
| `cors-checker.js` | CORS misconfiguration detector |
| `ssl-checker.js` | SSL/TLS certificate analyzer |

## Installation

```bash
# No dependencies required - uses Node.js built-in modules
npm install  # Optional, just links the bin commands
```

## Usage

### Header Checker
```bash
node header-checker.js https://example.com
node header-checker.js https://example.com --json
```

Checks for:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Information disclosure headers

### CORS Checker
```bash
node cors-checker.js https://api.example.com/endpoint
node cors-checker.js https://api.example.com --json
```

Tests for:
- Reflected origin vulnerabilities
- Wildcard origin with credentials
- Null origin acceptance
- Credential leakage risks

### SSL Checker
```bash
node ssl-checker.js example.com
node ssl-checker.js example.com:8443
node ssl-checker.js example.com --json
```

Checks:
- Certificate validity and expiration
- Certificate chain
- Protocol version (TLS 1.2, 1.3)
- Cipher strength
- Subject Alternative Names

## Features

- **Zero dependencies**: Uses Node.js built-in modules
- **JSON output**: Use `--json` for automation
- **Grading system**: Quick security assessment
- **Detailed findings**: Actionable security recommendations

## Requirements

- Node.js 14.0.0 or higher

## Output Grades

- **A**: Excellent security configuration
- **B**: Good, minor improvements possible
- **C**: Fair, some issues to address
- **D**: Poor, significant issues
- **F**: Failing, critical issues present
