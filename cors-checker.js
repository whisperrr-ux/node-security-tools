#!/usr/bin/env node
/**
 * cors-checker.js - CORS misconfiguration checker
 * Author: ByteCreeper
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const TEST_ORIGINS = [
  'https://evil.com',
  'https://attacker.example.com',
  'null',
  'https://example.com.evil.com', // Subdomain bypass attempt
];

async function checkCORS(targetUrl, origin) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const client = url.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'OPTIONS',
      timeout: 10000,
      rejectUnauthorized: false,
      headers: {
        'Origin': origin,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-Requested-With',
      },
    };
    
    const req = client.request(options, (res) => {
      resolve({
        origin: origin,
        statusCode: res.statusCode,
        acao: res.headers['access-control-allow-origin'],
        acac: res.headers['access-control-allow-credentials'],
        acam: res.headers['access-control-allow-methods'],
        acah: res.headers['access-control-allow-headers'],
      });
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    req.end();
  });
}

async function analyzeCORS(targetUrl) {
  const results = {
    url: targetUrl,
    corsEnabled: false,
    findings: [],
    severity: 'info',
    tests: [],
  };
  
  for (const origin of TEST_ORIGINS) {
    try {
      const response = await checkCORS(targetUrl, origin);
      results.tests.push(response);
      
      if (response.acao) {
        results.corsEnabled = true;
        
        // Check for wildcard
        if (response.acao === '*') {
          results.findings.push({
            type: 'wildcard_origin',
            severity: 'medium',
            message: 'CORS allows all origins (*)',
            origin: origin,
          });
          
          // Wildcard with credentials is critical
          if (response.acac === 'true') {
            results.findings.push({
              type: 'wildcard_with_credentials',
              severity: 'critical',
              message: 'CORS allows credentials with wildcard origin',
              origin: origin,
            });
            results.severity = 'critical';
          }
        }
        
        // Check for reflected origin
        if (response.acao === origin) {
          results.findings.push({
            type: 'reflected_origin',
            severity: 'high',
            message: `CORS reflects arbitrary origin: ${origin}`,
            origin: origin,
          });
          
          if (results.severity !== 'critical') {
            results.severity = 'high';
          }
          
          if (response.acac === 'true') {
            results.findings.push({
              type: 'reflected_with_credentials',
              severity: 'critical',
              message: 'Reflected origin with credentials allowed',
              origin: origin,
            });
            results.severity = 'critical';
          }
        }
        
        // Check for null origin
        if (response.acao === 'null') {
          results.findings.push({
            type: 'null_origin',
            severity: 'medium',
            message: 'CORS allows null origin (iframe/data URI attacks possible)',
            origin: origin,
          });
          if (results.severity === 'info') {
            results.severity = 'medium';
          }
        }
      }
    } catch (err) {
      // Ignore errors for individual tests
    }
  }
  
  // Also do a GET request to check
  try {
    const getResult = await new Promise((resolve, reject) => {
      const url = new URL(targetUrl);
      const client = url.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        timeout: 10000,
        rejectUnauthorized: false,
        headers: { 'Origin': 'https://evil.com' },
      };
      
      const req = client.request(options, (res) => {
        resolve({
          acao: res.headers['access-control-allow-origin'],
          acac: res.headers['access-control-allow-credentials'],
        });
      });
      
      req.on('error', reject);
      req.end();
    });
    
    if (getResult.acao && getResult.acao === 'https://evil.com') {
      if (!results.findings.some(f => f.type === 'reflected_origin')) {
        results.findings.push({
          type: 'reflected_origin_get',
          severity: 'high',
          message: 'GET request reflects arbitrary origin',
          origin: 'https://evil.com',
        });
        if (results.severity !== 'critical') {
          results.severity = 'high';
        }
      }
    }
  } catch (err) {
    // Ignore
  }
  
  return results;
}

function printResults(result, jsonOutput = false) {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  
  console.log('\n' + '='.repeat(60));
  console.log(`CORS Analysis: ${result.url}`);
  console.log('='.repeat(60));
  
  console.log(`\nCORS Enabled: ${result.corsEnabled ? 'Yes' : 'No'}`);
  console.log(`Overall Severity: ${result.severity.toUpperCase()}`);
  
  if (result.findings.length > 0) {
    console.log('\n[Findings]');
    for (const finding of result.findings) {
      const prefix = finding.severity === 'critical' ? '[!!]' : 
                     finding.severity === 'high' ? '[!]' : 
                     finding.severity === 'medium' ? '[~]' : '[*]';
      console.log(`  ${prefix} ${finding.message}`);
    }
  } else if (result.corsEnabled) {
    console.log('\n[+] No CORS misconfigurations detected');
  } else {
    console.log('\n[*] CORS not enabled on this endpoint');
  }
  
  if (result.tests.length > 0) {
    console.log('\n[Test Results]');
    for (const test of result.tests) {
      if (test.acao) {
        console.log(`  Origin: ${test.origin}`);
        console.log(`    ACAO: ${test.acao}`);
        console.log(`    ACAC: ${test.acac || 'not set'}`);
      }
    }
  }
}

// CLI
const args = process.argv.slice(2);
let url = '';
let jsonOutput = false;

for (const arg of args) {
  if (arg === '--json' || arg === '-j') {
    jsonOutput = true;
  } else if (arg === '--help' || arg === '-h') {
    console.log('Usage: node cors-checker.js <url> [options]');
    console.log('\nOptions:');
    console.log('  -j, --json    Output as JSON');
    console.log('\nExamples:');
    console.log('  node cors-checker.js https://api.example.com/endpoint');
    process.exit(0);
  } else if (!arg.startsWith('-')) {
    url = arg;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
  }
}

if (!url) {
  console.error('Error: No URL specified');
  console.error('Usage: node cors-checker.js <url>');
  process.exit(1);
}

(async () => {
  try {
    console.error(`[*] Analyzing CORS for: ${url}`);
    const result = await analyzeCORS(url);
    printResults(result, jsonOutput);
  } catch (err) {
    console.error(`[!] Error: ${err.message}`);
    process.exit(1);
  }
})();
