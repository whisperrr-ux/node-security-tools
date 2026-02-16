#!/usr/bin/env node
/**
 * cors-check.js - CORS misconfiguration scanner
 * Author: ByteCreeper (bytecreeper@proton.me)
 * Usage: node cors-check.js <url> [--json]
 */

const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const url = args.find(a => !a.startsWith('--'));

if (!url) {
  console.error('Usage: node cors-check.js <url> [--json]');
  process.exit(1);
}

const MALICIOUS_ORIGINS = [
  'https://evil.com',
  'https://attacker.com',
  'null',
  'https://example.com.evil.com',
];

async function checkCORS(targetUrl) {
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const parsedUrl = new URL(targetUrl);
  const baseOrigin = `${parsedUrl.protocol}//${parsedUrl.host}`;

  const result = {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    tests: [],
    vulnerabilities: [],
    summary: {
      total_tests: 0,
      vulnerable: 0,
      secure: 0
    }
  };

  // Test origins to check
  const testOrigins = [
    { origin: baseOrigin, name: 'Same origin', expected: 'allowed' },
    { origin: 'https://evil.com', name: 'Arbitrary origin', expected: 'blocked' },
    { origin: 'null', name: 'Null origin', expected: 'blocked' },
    { origin: `https://${parsedUrl.host}.evil.com`, name: 'Subdomain spoof', expected: 'blocked' },
    { origin: `https://evil${parsedUrl.host}`, name: 'Prefix attack', expected: 'blocked' },
    { origin: baseOrigin.replace('https://', 'http://'), name: 'HTTP downgrade', expected: 'blocked' },
  ];

  for (const test of testOrigins) {
    try {
      const response = await fetch(targetUrl, {
        method: 'OPTIONS',
        headers: {
          'Origin': test.origin,
          'Access-Control-Request-Method': 'GET'
        }
      });

      const acao = response.headers.get('access-control-allow-origin');
      const acac = response.headers.get('access-control-allow-credentials');

      const testResult = {
        test: test.name,
        origin_sent: test.origin,
        acao_received: acao || 'none',
        credentials_allowed: acac === 'true',
        reflected: acao === test.origin,
        wildcard: acao === '*',
        status: 'secure'
      };

      // Check for vulnerabilities
      if (test.expected === 'blocked') {
        if (acao === test.origin) {
          testResult.status = 'vulnerable';
          testResult.issue = 'Origin reflected - potential CORS misconfiguration';
          result.vulnerabilities.push({
            type: 'Origin Reflection',
            origin: test.origin,
            severity: acac === 'true' ? 'HIGH' : 'MEDIUM',
            detail: `Server reflects arbitrary origin: ${test.origin}`,
            credentials: acac === 'true'
          });
        } else if (acao === '*' && acac === 'true') {
          testResult.status = 'vulnerable';
          testResult.issue = 'Wildcard with credentials - critical misconfiguration';
          result.vulnerabilities.push({
            type: 'Wildcard with Credentials',
            severity: 'CRITICAL',
            detail: 'Access-Control-Allow-Origin: * with credentials enabled'
          });
        } else if (acao === '*') {
          testResult.status = 'warning';
          testResult.issue = 'Wildcard CORS - may be intentional for public APIs';
        }
      }

      result.tests.push(testResult);
      result.summary.total_tests++;
      
      if (testResult.status === 'vulnerable') {
        result.summary.vulnerable++;
      } else {
        result.summary.secure++;
      }

    } catch (error) {
      result.tests.push({
        test: test.name,
        origin_sent: test.origin,
        error: error.message,
        status: 'error'
      });
      result.summary.total_tests++;
    }
  }

  // Determine overall risk
  if (result.vulnerabilities.some(v => v.severity === 'CRITICAL')) {
    result.risk_level = 'CRITICAL';
  } else if (result.vulnerabilities.some(v => v.severity === 'HIGH')) {
    result.risk_level = 'HIGH';
  } else if (result.vulnerabilities.some(v => v.severity === 'MEDIUM')) {
    result.risk_level = 'MEDIUM';
  } else if (result.vulnerabilities.length > 0) {
    result.risk_level = 'LOW';
  } else {
    result.risk_level = 'NONE';
  }

  return result;
}

function printResults(result) {
  console.log(`\nCORS Misconfiguration Scanner`);
  console.log('='.repeat(60));
  console.log(`Target: ${result.url}`);
  console.log(`Risk Level: ${result.risk_level}`);
  console.log(`\nTests: ${result.summary.total_tests} | Vulnerable: ${result.summary.vulnerable} | Secure: ${result.summary.secure}`);
  
  console.log('\n--- Test Results ---');
  for (const test of result.tests) {
    const icon = test.status === 'vulnerable' ? '!' : test.status === 'warning' ? '?' : test.status === 'error' ? 'x' : '+';
    console.log(`\n[${icon}] ${test.test}`);
    console.log(`    Origin: ${test.origin_sent}`);
    console.log(`    ACAO:   ${test.acao_received}`);
    if (test.credentials_allowed) {
      console.log(`    Credentials: ALLOWED`);
    }
    if (test.issue) {
      console.log(`    Issue: ${test.issue}`);
    }
    if (test.error) {
      console.log(`    Error: ${test.error}`);
    }
  }

  if (result.vulnerabilities.length > 0) {
    console.log('\n--- Vulnerabilities Found ---');
    for (const vuln of result.vulnerabilities) {
      console.log(`\n[${vuln.severity}] ${vuln.type}`);
      console.log(`  ${vuln.detail}`);
      if (vuln.credentials) {
        console.log(`  WARNING: Credentials are allowed - this can leak sensitive data!`);
      }
    }
  }

  console.log('\n' + '='.repeat(60));
}

// Main
checkCORS(url).then(result => {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResults(result);
  }
});
