# node-security-tools

Web security reconnaissance and analysis tools built with Node.js. Zero external dependencies - uses only Node.js built-in modules (requires Node 18+).

## Tools

| Tool | Description |
|------|-------------|
| `header-scan.js` | HTTP security header analyzer with scoring |
| `cors-check.js` | CORS misconfiguration scanner |
| `subdomain-enum.js` | Passive subdomain enumeration using public sources |
| `tech-detect.js` | Web technology fingerprinting |
| `link-extractor.js` | Extract and analyze links, forms, and resources |

## Requirements

Node.js 18 or later (uses built-in fetch API).

## Usage Examples

### Security Header Scanner

Analyzes HTTP security headers and provides a security score.

```bash
# Basic scan
node header-scan.js https://example.com

# JSON output
node header-scan.js example.com --json
```

Output includes:
- Present security headers with values
- Missing security headers with recommendations
- Security score (0-100%) and grade (A-F)
- Server information disclosure check

### CORS Misconfiguration Scanner

Tests for common CORS misconfigurations that could allow data theft.

```bash
# Scan for CORS issues
node cors-check.js https://api.example.com

# JSON output
node cors-check.js api.example.com --json
```

Tests performed:
- Arbitrary origin reflection
- Null origin acceptance
- Subdomain spoofing
- HTTP downgrade attacks
- Wildcard with credentials

### Subdomain Enumeration

Discovers subdomains using passive sources and active bruteforce.

```bash
# Enumerate subdomains
node subdomain-enum.js example.com

# JSON output with full details
node subdomain-enum.js example.com --json
```

Sources:
- crt.sh certificate transparency logs
- Common subdomain wordlist bruteforce
- DNS resolution verification

### Technology Detection

Fingerprints web technologies, frameworks, and services.

```bash
# Detect technologies
node tech-detect.js https://example.com

# JSON output
node tech-detect.js example.com --json
```

Detects:
- Web servers (nginx, Apache, IIS, etc.)
- Frameworks (React, Vue, Angular, Express, Django, etc.)
- CMS (WordPress, Drupal, Shopify, etc.)
- CDN providers (Cloudflare, Akamai, etc.)
- Security products (WAF, etc.)
- Analytics platforms

### Link Extractor

Extracts and categorizes all links from a web page.

```bash
# Extract all links
node link-extractor.js https://example.com

# External links only
node link-extractor.js example.com --external

# Include JavaScript files and forms
node link-extractor.js example.com --js --forms

# JSON output
node link-extractor.js example.com --json
```

Extracts:
- Internal, external, and subdomain links
- JavaScript and CSS resources
- Form actions and methods
- Email addresses
- Interesting paths (admin, api, backup, etc.)

## JSON Output

All tools support `--json` flag for structured output. This makes it easy to:
- Pipe to `jq` for processing
- Import into other tools
- Store results for comparison

```bash
# Example: Extract just external links with jq
node link-extractor.js example.com --json | jq '.links.external'

# Example: Get security score
node header-scan.js example.com --json | jq '.security.score'
```

## Combining Tools

Chain tools for comprehensive reconnaissance:

```bash
# Enumerate subdomains, then scan each for headers
node subdomain-enum.js example.com --json | \
  jq -r '.alive[].subdomain' | \
  while read sub; do
    echo "Scanning $sub..."
    node header-scan.js "$sub" --json >> results.json
  done
```

## Author

ByteCreeper (bytecreeper@proton.me)

## Disclaimer

These tools are for authorized security testing and educational purposes only. Obtain proper authorization before scanning systems you do not own.
