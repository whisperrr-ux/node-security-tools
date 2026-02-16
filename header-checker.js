#!/usr/bin/env node
/**
 * header-checker.js - HTTP security header analyzer
 * Author: ByteCreeper
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security',
    description: 'Enforces HTTPS connections',
    severity: 'high',
  },
  'content-security-policy': {
    name: 'Content-Security-Policy',
    description: 'Controls resource loading',
    severity: 'high',
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME sniffing',
    expected: 'nosniff',
    severity: 'medium',
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking',
    expected: ['DENY', 'SAMEORIGIN'],
    severity: 'medium',
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    description: 'XSS filter (legacy)',
    severity: 'low',
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls referrer information',
    severity: 'low',
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Controls browser features',
    severity: 'low',
  },
  'cross-origin-opener-policy': {
    name: 'Cross-Origin-Opener-Policy',
    description: 'Isolates browsing context',
    severity: 'low',
  },
  'cross-origin-resource-policy': {
    name: 'Cross-Origin-Resource-Policy',
    description: 'Controls resource sharing',
    severity: 'low',
  },
};

const INFO_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version'];

async function checkHeaders(targetUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const client = url.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      timeout: 10000,
      rejectUnauthorized: false,
    };
    
    const req = client.request(options, (res) => {
      const result = {
        url: targetUrl,
        statusCode: res.statusCode,
        headers: res.headers,
        present: {},
        missing: [],
        issues: [],
        infoDisclosure: [],
        grade: 'F',
      };
      
      // Check security headers
      for (const [key, config] of Object.entries(SECURITY_HEADERS)) {
        const value = res.headers[key];
        
        if (value) {
          result.present[config.name] = value;
          
          // Check expected values
          if (config.expected) {
            const expectedList = Array.isArray(config.expected) 
              ? config.expected 
              : [config.expected];
            
            if (!expectedList.some(e => value.toUpperCase().includes(e.toUpperCase()))) {
              result.issues.push({
                header: config.name,
                issue: `Unexpected value: ${value}`,
                severity: 'low',
              });
            }
          }
        } else {
          result.missing.push({
            header: config.name,
            description: config.description,
            severity: config.severity,
          });
        }
      }
      
      // Check information disclosure
      for (const header of INFO_HEADERS) {
        if (res.headers[header]) {
          result.infoDisclosure.push({
            header: header,
            value: res.headers[header],
          });
        }
      }
      
      // Calculate grade
      const highMissing = result.missing.filter(m => m.severity === 'high').length;
      const mediumMissing = result.missing.filter(m => m.severity === 'medium').length;
      
      if (highMissing === 0 && mediumMissing === 0) {
        result.grade = 'A';
      } else if (highMissing === 0 && mediumMissing <= 1) {
        result.grade = 'B';
      } else if (highMissing <= 1) {
        result.grade = 'C';
      } else if (highMissing <= 2) {
        result.grade = 'D';
      } else {
        result.grade = 'F';
      }
      
      resolve(result);
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    req.end();
  });
}

function printResults(result, jsonOutput = false) {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  
  console.log('\n' + '='.repeat(60));
  console.log(`Security Header Analysis: ${result.url}`);
  console.log(`Grade: ${result.grade}`);
  console.log('='.repeat(60));
  
  console.log('\n[Present Headers]');
  for (const [name, value] of Object.entries(result.present)) {
    const shortValue = value.length > 50 ? value.substring(0, 50) + '...' : value;
    console.log(`  [+] ${name}: ${shortValue}`);
  }
  
  if (result.missing.length > 0) {
    console.log('\n[Missing Headers]');
    for (const m of result.missing) {
      const severity = m.severity.toUpperCase();
      console.log(`  [-] ${m.header} (${severity})`);
      console.log(`      ${m.description}`);
    }
  }
  
  if (result.issues.length > 0) {
    console.log('\n[Issues]');
    for (const issue of result.issues) {
      console.log(`  [!] ${issue.header}: ${issue.issue}`);
    }
  }
  
  if (result.infoDisclosure.length > 0) {
    console.log('\n[Information Disclosure]');
    for (const info of result.infoDisclosure) {
      console.log(`  [!] ${info.header}: ${info.value}`);
    }
  }
}

// CLI
const args = process.argv.slice(2);
let urls = [];
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--json' || args[i] === '-j') {
    jsonOutput = true;
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log('Usage: node header-checker.js <url> [options]');
    console.log('\nOptions:');
    console.log('  -j, --json    Output as JSON');
    console.log('\nExamples:');
    console.log('  node header-checker.js https://example.com');
    console.log('  node header-checker.js https://example.com --json');
    process.exit(0);
  } else if (!args[i].startsWith('-')) {
    let url = args[i];
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    urls.push(url);
  }
}

if (urls.length === 0) {
  console.error('Error: No URL specified');
  console.error('Usage: node header-checker.js <url>');
  process.exit(1);
}

(async () => {
  const results = [];
  
  for (const url of urls) {
    try {
      console.error(`[*] Checking: ${url}`);
      const result = await checkHeaders(url);
      results.push(result);
      
      if (!jsonOutput) {
        printResults(result);
      }
    } catch (err) {
      console.error(`[!] Error checking ${url}: ${err.message}`);
    }
  }
  
  if (jsonOutput) {
    console.log(JSON.stringify(results, null, 2));
  }
})();
