#!/usr/bin/env node
/**
 * ssl-checker.js - SSL/TLS certificate analyzer
 * Author: ByteCreeper
 */

const tls = require('tls');
const https = require('https');
const { URL } = require('url');

async function checkSSL(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 10000,
    };
    
    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      
      const result = {
        hostname: hostname,
        port: port,
        connected: true,
        authorized: authorized,
        authError: authError,
        protocol: protocol,
        cipher: cipher ? {
          name: cipher.name,
          version: cipher.version,
          bits: cipher.bits,
        } : null,
        certificate: null,
        chain: [],
        issues: [],
      };
      
      if (cert && Object.keys(cert).length > 0) {
        // Parse certificate
        result.certificate = {
          subject: cert.subject,
          issuer: cert.issuer,
          serialNumber: cert.serialNumber,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          fingerprint: cert.fingerprint,
          fingerprint256: cert.fingerprint256,
          subjectAltNames: [],
        };
        
        // Parse SAN
        if (cert.subjectaltname) {
          result.certificate.subjectAltNames = cert.subjectaltname
            .split(', ')
            .map(s => s.replace('DNS:', ''));
        }
        
        // Check expiration
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        
        result.certificate.daysRemaining = daysRemaining;
        result.certificate.expired = daysRemaining < 0;
        
        if (daysRemaining < 0) {
          result.issues.push({
            type: 'expired',
            severity: 'critical',
            message: `Certificate expired ${Math.abs(daysRemaining)} days ago`,
          });
        } else if (daysRemaining < 30) {
          result.issues.push({
            type: 'expiring_soon',
            severity: 'warning',
            message: `Certificate expires in ${daysRemaining} days`,
          });
        }
        
        // Build certificate chain
        let currentCert = cert;
        while (currentCert) {
          result.chain.push({
            subject: currentCert.subject?.CN || 'Unknown',
            issuer: currentCert.issuer?.CN || 'Unknown',
          });
          currentCert = currentCert.issuerCertificate;
          
          // Prevent infinite loop for self-signed
          if (currentCert === cert || result.chain.length > 10) {
            break;
          }
        }
        
        // Check for self-signed
        if (cert.subject?.CN === cert.issuer?.CN) {
          result.issues.push({
            type: 'self_signed',
            severity: 'warning',
            message: 'Certificate is self-signed',
          });
        }
      }
      
      // Check authorization
      if (!authorized) {
        result.issues.push({
          type: 'not_trusted',
          severity: 'warning',
          message: `Certificate not trusted: ${authError}`,
        });
      }
      
      // Check protocol version
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        result.issues.push({
          type: 'weak_protocol',
          severity: 'medium',
          message: `Weak protocol: ${protocol}`,
        });
      }
      
      // Check cipher strength
      if (cipher && cipher.bits < 128) {
        result.issues.push({
          type: 'weak_cipher',
          severity: 'high',
          message: `Weak cipher: ${cipher.name} (${cipher.bits} bits)`,
        });
      }
      
      socket.end();
      resolve(result);
    });
    
    socket.on('error', (err) => {
      resolve({
        hostname: hostname,
        port: port,
        connected: false,
        error: err.message,
      });
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        hostname: hostname,
        port: port,
        connected: false,
        error: 'Connection timeout',
      });
    });
  });
}

function calculateGrade(result) {
  if (!result.connected) return 'N/A';
  
  let score = 100;
  
  for (const issue of result.issues) {
    switch (issue.severity) {
      case 'critical':
        score -= 50;
        break;
      case 'high':
        score -= 30;
        break;
      case 'medium':
        score -= 15;
        break;
      case 'warning':
        score -= 5;
        break;
    }
  }
  
  if (!result.authorized) {
    score -= 20;
  }
  
  if (result.protocol === 'TLSv1.3') {
    score += 10;
  }
  
  score = Math.max(0, Math.min(100, score));
  
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function printResults(result, jsonOutput = false) {
  result.grade = calculateGrade(result);
  
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  
  console.log('\n' + '='.repeat(60));
  console.log(`SSL/TLS Analysis: ${result.hostname}:${result.port}`);
  console.log(`Grade: ${result.grade}`);
  console.log('='.repeat(60));
  
  if (!result.connected) {
    console.log(`\n[!] Connection failed: ${result.error}`);
    return;
  }
  
  console.log(`\n[Connection]`);
  console.log(`  Protocol: ${result.protocol}`);
  console.log(`  Cipher: ${result.cipher?.name} (${result.cipher?.bits} bits)`);
  console.log(`  Authorized: ${result.authorized ? 'Yes' : 'No'}`);
  
  if (result.certificate) {
    console.log(`\n[Certificate]`);
    console.log(`  Subject: ${result.certificate.subject?.CN || 'Unknown'}`);
    console.log(`  Issuer: ${result.certificate.issuer?.CN || 'Unknown'}`);
    console.log(`  Valid From: ${result.certificate.validFrom}`);
    console.log(`  Valid To: ${result.certificate.validTo}`);
    console.log(`  Days Remaining: ${result.certificate.daysRemaining}`);
    
    if (result.certificate.subjectAltNames.length > 0) {
      console.log(`  SANs: ${result.certificate.subjectAltNames.slice(0, 5).join(', ')}` + 
        (result.certificate.subjectAltNames.length > 5 ? '...' : ''));
    }
  }
  
  if (result.chain.length > 0) {
    console.log(`\n[Certificate Chain]`);
    result.chain.forEach((c, i) => {
      console.log(`  ${i + 1}. ${c.subject} (issued by: ${c.issuer})`);
    });
  }
  
  if (result.issues.length > 0) {
    console.log(`\n[Issues]`);
    for (const issue of result.issues) {
      const prefix = issue.severity === 'critical' ? '[!!]' : 
                     issue.severity === 'high' ? '[!]' : 
                     issue.severity === 'medium' ? '[~]' : '[*]';
      console.log(`  ${prefix} ${issue.message}`);
    }
  } else {
    console.log(`\n[+] No issues detected`);
  }
}

// CLI
const args = process.argv.slice(2);
let target = '';
let jsonOutput = false;

for (const arg of args) {
  if (arg === '--json' || arg === '-j') {
    jsonOutput = true;
  } else if (arg === '--help' || arg === '-h') {
    console.log('Usage: node ssl-checker.js <hostname[:port]> [options]');
    console.log('\nOptions:');
    console.log('  -j, --json    Output as JSON');
    console.log('\nExamples:');
    console.log('  node ssl-checker.js example.com');
    console.log('  node ssl-checker.js example.com:8443 --json');
    process.exit(0);
  } else if (!arg.startsWith('-')) {
    target = arg;
  }
}

if (!target) {
  console.error('Error: No hostname specified');
  console.error('Usage: node ssl-checker.js <hostname[:port]>');
  process.exit(1);
}

// Parse hostname:port
let hostname = target;
let port = 443;

if (target.includes(':')) {
  const parts = target.split(':');
  hostname = parts[0];
  port = parseInt(parts[1], 10);
}

// Remove protocol if present
hostname = hostname.replace(/^https?:\/\//, '').split('/')[0];

(async () => {
  try {
    console.error(`[*] Checking SSL/TLS for: ${hostname}:${port}`);
    const result = await checkSSL(hostname, port);
    printResults(result, jsonOutput);
  } catch (err) {
    console.error(`[!] Error: ${err.message}`);
    process.exit(1);
  }
})();
