#!/usr/bin/env node
/**
 * subdomain-enum.js - Passive subdomain enumeration using public sources
 * Author: ByteCreeper (bytecreeper@proton.me)
 * Usage: node subdomain-enum.js <domain> [--json]
 */

import dns from 'dns';
import { promisify } from 'util';

const resolve4 = promisify(dns.resolve4);
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const domain = args.find(a => !a.startsWith('--'));

if (!domain) {
  console.error('Usage: node subdomain-enum.js <domain> [--json]');
  process.exit(1);
}

// Common subdomains for active bruteforce
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'dns',
  'vpn', 'remote', 'api', 'app', 'dev', 'staging', 'test', 'beta', 'admin',
  'portal', 'secure', 'login', 'sso', 'auth', 'gateway', 'cdn', 'static',
  'assets', 'img', 'images', 'media', 'blog', 'shop', 'store', 'support',
  'help', 'docs', 'status', 'git', 'gitlab', 'jenkins', 'ci', 'jira',
  'confluence', 'wiki', 'forum', 'mx', 'mx1', 'mx2', 'ns', 'dns1', 'dns2',
  'm', 'mobile', 'internal', 'intranet', 'extranet', 'db', 'database',
  'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'kibana', 'grafana',
  'monitor', 'nagios', 'prometheus', 'logs', 'splunk', 's3', 'storage',
  'backup', 'old', 'new', 'legacy', 'demo', 'sandbox', 'uat', 'qa', 'prod'
];

async function fetchCrtSh(domain) {
  try {
    const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) return [];
    
    const data = await response.json();
    const subdomains = new Set();
    
    for (const entry of data) {
      const name = entry.name_value;
      // Handle wildcards and multi-line entries
      const names = name.split('\n').map(n => n.replace('*.', '').trim().toLowerCase());
      for (const n of names) {
        if (n.endsWith(domain) && !n.includes('*')) {
          subdomains.add(n);
        }
      }
    }
    return [...subdomains];
  } catch (error) {
    return [];
  }
}

async function checkSubdomain(subdomain) {
  try {
    const addresses = await resolve4(subdomain);
    return { subdomain, addresses, alive: true };
  } catch {
    return { subdomain, addresses: [], alive: false };
  }
}

async function enumerateSubdomains(targetDomain) {
  const result = {
    domain: targetDomain,
    timestamp: new Date().toISOString(),
    sources: {},
    subdomains: [],
    alive: [],
    summary: {
      total_found: 0,
      alive_count: 0
    }
  };

  if (!jsonOutput) {
    console.log(`\nSubdomain Enumeration: ${targetDomain}`);
    console.log('='.repeat(50));
    console.log('\n[*] Querying passive sources...');
  }

  // Passive enumeration from crt.sh
  const crtSubdomains = await fetchCrtSh(targetDomain);
  result.sources['crt.sh'] = crtSubdomains.length;
  
  if (!jsonOutput) {
    console.log(`    crt.sh: ${crtSubdomains.length} entries`);
  }

  // Active bruteforce of common subdomains
  if (!jsonOutput) {
    console.log('\n[*] Bruteforcing common subdomains...');
  }
  
  const bruteSubdomains = COMMON_SUBDOMAINS.map(s => `${s}.${targetDomain}`);
  result.sources['bruteforce'] = bruteSubdomains.length;

  // Combine and dedupe
  const allSubdomains = [...new Set([
    targetDomain, // Include base domain
    ...crtSubdomains,
    ...bruteSubdomains
  ])].sort();

  result.subdomains = allSubdomains;
  result.summary.total_found = allSubdomains.length;

  if (!jsonOutput) {
    console.log(`\n[*] Checking ${allSubdomains.length} subdomains for DNS resolution...`);
  }

  // Check which are alive (batch for performance)
  const batchSize = 20;
  for (let i = 0; i < allSubdomains.length; i += batchSize) {
    const batch = allSubdomains.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(checkSubdomain));
    
    for (const r of results) {
      if (r.alive) {
        result.alive.push({
          subdomain: r.subdomain,
          addresses: r.addresses
        });
        
        if (!jsonOutput) {
          console.log(`    [+] ${r.subdomain} -> ${r.addresses.join(', ')}`);
        }
      }
    }
  }

  result.summary.alive_count = result.alive.length;
  return result;
}

function printSummary(result) {
  console.log('\n' + '='.repeat(50));
  console.log(`\nSummary for ${result.domain}:`);
  console.log(`  Total discovered: ${result.summary.total_found}`);
  console.log(`  Alive (resolving): ${result.summary.alive_count}`);
  console.log(`\nSources:`);
  for (const [source, count] of Object.entries(result.sources)) {
    console.log(`  - ${source}: ${count}`);
  }

  if (result.alive.length > 0) {
    console.log(`\nAlive Subdomains:`);
    for (const sub of result.alive) {
      console.log(`  ${sub.subdomain}`);
      for (const ip of sub.addresses) {
        console.log(`    -> ${ip}`);
      }
    }
  }
}

// Main
enumerateSubdomains(domain).then(result => {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printSummary(result);
  }
});
