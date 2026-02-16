#!/usr/bin/env node
/**
 * header-scan.js - HTTP security header analyzer
 * Author: ByteCreeper (bytecreeper@proton.me)
 * Usage: node header-scan.js <url> [--json]
 */

const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const url = args.find(a => !a.startsWith('--'));

if (!url) {
  console.error('Usage: node header-scan.js <url> [--json]');
  process.exit(1);
}

const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security',
    description: 'Enforces HTTPS connections',
    severity: 'high',
    recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  'content-security-policy': {
    name: 'Content-Security-Policy',
    description: 'Prevents XSS and injection attacks',
    severity: 'high',
    recommendation: 'Add a CSP header appropriate for your application'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking attacks',
    severity: 'medium',
    recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME type sniffing',
    severity: 'medium',
    recommendation: 'Add: X-Content-Type-Options: nosniff'
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    description: 'Legacy XSS filter (deprecated but still useful)',
    severity: 'low',
    recommendation: 'Add: X-XSS-Protection: 1; mode=block'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls referrer information leakage',
    severity: 'low',
    recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Controls browser feature access',
    severity: 'low',
    recommendation: 'Add: Permissions-Policy: geolocation=(), microphone=()'
  },
  'x-permitted-cross-domain-policies': {
    name: 'X-Permitted-Cross-Domain-Policies',
    description: 'Restricts Adobe Flash/PDF cross-domain requests',
    severity: 'low',
    recommendation: 'Add: X-Permitted-Cross-Domain-Policies: none'
  }
};

async function scanHeaders(targetUrl) {
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const result = {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    headers: {},
    security: {
      present: [],
      missing: [],
      score: 0
    },
    info: {}
  };

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow'
    });

    result.status = response.status;
    result.statusText = response.statusText;
    
    // Collect all headers
    for (const [key, value] of response.headers) {
      result.headers[key] = value;
    }

    // Extract interesting headers
    result.info.server = response.headers.get('server') || 'Not disclosed';
    result.info.poweredBy = response.headers.get('x-powered-by') || 'Not disclosed';
    result.info.contentType = response.headers.get('content-type') || 'Unknown';

    // Check security headers
    for (const [headerKey, headerInfo] of Object.entries(SECURITY_HEADERS)) {
      const value = response.headers.get(headerKey);
      if (value) {
        result.security.present.push({
          header: headerInfo.name,
          value: value,
          severity: headerInfo.severity
        });
      } else {
        result.security.missing.push({
          header: headerInfo.name,
          description: headerInfo.description,
          severity: headerInfo.severity,
          recommendation: headerInfo.recommendation
        });
      }
    }

    // Calculate security score
    const total = Object.keys(SECURITY_HEADERS).length;
    result.security.score = Math.round((result.security.present.length / total) * 100);
    result.security.grade = getGrade(result.security.score);

  } catch (error) {
    result.error = error.message;
  }

  return result;
}

function getGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function printResults(result) {
  console.log(`\nSecurity Header Scan: ${result.url}`);
  console.log('='.repeat(60));
  
  if (result.error) {
    console.log(`\nError: ${result.error}`);
    return;
  }

  console.log(`\nStatus: ${result.status} ${result.statusText}`);
  console.log(`Server: ${result.info.server}`);
  if (result.info.poweredBy !== 'Not disclosed') {
    console.log(`X-Powered-By: ${result.info.poweredBy} (consider removing)`);
  }

  console.log(`\n--- Security Score: ${result.security.score}% (Grade: ${result.security.grade}) ---`);
  
  if (result.security.present.length > 0) {
    console.log('\n[PRESENT] Security Headers:');
    for (const h of result.security.present) {
      console.log(`  + ${h.header}: ${h.value.substring(0, 60)}${h.value.length > 60 ? '...' : ''}`);
    }
  }

  if (result.security.missing.length > 0) {
    console.log('\n[MISSING] Security Headers:');
    for (const h of result.security.missing) {
      const sev = h.severity.toUpperCase();
      console.log(`  - ${h.header} [${sev}]`);
      console.log(`    ${h.description}`);
    }
  }

  console.log('\n' + '='.repeat(60));
}

// Main
scanHeaders(url).then(result => {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResults(result);
  }
});
