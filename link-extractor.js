#!/usr/bin/env node
/**
 * link-extractor.js - Extract and analyze links from web pages
 * Author: ByteCreeper (bytecreeper@proton.me)
 * Usage: node link-extractor.js <url> [--json] [--external] [--js] [--forms]
 */

const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const externalOnly = args.includes('--external');
const includeJs = args.includes('--js');
const includeForms = args.includes('--forms');
const url = args.find(a => !a.startsWith('--'));

if (!url) {
  console.error('Usage: node link-extractor.js <url> [--json] [--external] [--js] [--forms]');
  console.error('  --external  Show only external links');
  console.error('  --js        Include JavaScript file references');
  console.error('  --forms     Include form actions');
  process.exit(1);
}

async function extractLinks(targetUrl) {
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const parsedBase = new URL(targetUrl);
  const baseDomain = parsedBase.hostname;

  const result = {
    url: targetUrl,
    baseDomain: baseDomain,
    timestamp: new Date().toISOString(),
    links: {
      internal: [],
      external: [],
      subdomains: []
    },
    resources: {
      scripts: [],
      stylesheets: [],
      images: []
    },
    forms: [],
    emails: [],
    interesting: [],
    summary: {}
  };

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow'
    });

    result.status = response.status;
    result.finalUrl = response.url;
    
    const body = await response.text();

    // Extract href links
    const hrefRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(body)) !== null) {
      processLink(match[1], result, baseDomain, targetUrl);
    }

    // Extract src attributes (images, scripts)
    const srcRegex = /src=["']([^"']+)["']/gi;
    while ((match = srcRegex.exec(body)) !== null) {
      const src = match[1];
      if (/\.js(\?|$)/i.test(src)) {
        result.resources.scripts.push(normalizeUrl(src, targetUrl));
      } else if (/\.(png|jpg|jpeg|gif|svg|webp|ico)(\?|$)/i.test(src)) {
        result.resources.images.push(normalizeUrl(src, targetUrl));
      }
    }

    // Extract stylesheet links
    const cssRegex = /href=["']([^"']+\.css[^"']*)["']/gi;
    while ((match = cssRegex.exec(body)) !== null) {
      result.resources.stylesheets.push(normalizeUrl(match[1], targetUrl));
    }

    // Extract form actions
    const formRegex = /<form[^>]*action=["']([^"']+)["'][^>]*>/gi;
    while ((match = formRegex.exec(body)) !== null) {
      const action = normalizeUrl(match[1], targetUrl);
      const methodMatch = match[0].match(/method=["']([^"']+)["']/i);
      result.forms.push({
        action: action,
        method: methodMatch ? methodMatch[1].toUpperCase() : 'GET'
      });
    }

    // Extract emails
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = body.match(emailRegex) || [];
    result.emails = [...new Set(emails)];

    // Find interesting paths
    const interestingPaths = [
      /\/admin/i, /\/login/i, /\/api\//i, /\/backup/i, /\/config/i,
      /\/debug/i, /\/test/i, /\/dev/i, /\.git/i, /\.env/i,
      /\/wp-admin/i, /\/phpmyadmin/i, /\/dashboard/i, /\/console/i
    ];

    const allLinks = [...result.links.internal, ...result.links.external, ...result.links.subdomains];
    for (const link of allLinks) {
      for (const pattern of interestingPaths) {
        if (pattern.test(link)) {
          if (!result.interesting.includes(link)) {
            result.interesting.push(link);
          }
          break;
        }
      }
    }

    // Dedupe
    result.links.internal = [...new Set(result.links.internal)].sort();
    result.links.external = [...new Set(result.links.external)].sort();
    result.links.subdomains = [...new Set(result.links.subdomains)].sort();
    result.resources.scripts = [...new Set(result.resources.scripts)].sort();
    result.resources.stylesheets = [...new Set(result.resources.stylesheets)].sort();
    result.interesting = [...new Set(result.interesting)].sort();

    // Summary
    result.summary = {
      internal_links: result.links.internal.length,
      external_links: result.links.external.length,
      subdomain_links: result.links.subdomains.length,
      scripts: result.resources.scripts.length,
      stylesheets: result.resources.stylesheets.length,
      forms: result.forms.length,
      emails: result.emails.length,
      interesting: result.interesting.length
    };

  } catch (error) {
    result.error = error.message;
  }

  return result;
}

function normalizeUrl(link, baseUrl) {
  try {
    return new URL(link, baseUrl).href;
  } catch {
    return link;
  }
}

function processLink(link, result, baseDomain, baseUrl) {
  // Skip anchors, javascript, mailto
  if (link.startsWith('#') || link.startsWith('javascript:') || link.startsWith('data:')) {
    return;
  }

  if (link.startsWith('mailto:')) {
    const email = link.replace('mailto:', '').split('?')[0];
    if (!result.emails.includes(email)) {
      result.emails.push(email);
    }
    return;
  }

  try {
    const fullUrl = new URL(link, baseUrl);
    const linkDomain = fullUrl.hostname;

    if (linkDomain === baseDomain) {
      result.links.internal.push(fullUrl.href);
    } else if (linkDomain.endsWith('.' + baseDomain)) {
      result.links.subdomains.push(fullUrl.href);
    } else {
      result.links.external.push(fullUrl.href);
    }
  } catch {
    // Invalid URL, skip
  }
}

function printResults(result) {
  console.log(`\nLink Extraction: ${result.url}`);
  console.log('='.repeat(60));
  
  if (result.error) {
    console.log(`\nError: ${result.error}`);
    return;
  }

  console.log(`\nStatus: ${result.status}`);
  console.log(`Base Domain: ${result.baseDomain}`);

  if (!externalOnly && result.links.internal.length > 0) {
    console.log(`\n--- Internal Links (${result.links.internal.length}) ---`);
    for (const link of result.links.internal.slice(0, 20)) {
      console.log(`  ${link}`);
    }
    if (result.links.internal.length > 20) {
      console.log(`  ... and ${result.links.internal.length - 20} more`);
    }
  }

  if (result.links.subdomains.length > 0) {
    console.log(`\n--- Subdomain Links (${result.links.subdomains.length}) ---`);
    for (const link of result.links.subdomains) {
      console.log(`  ${link}`);
    }
  }

  if (result.links.external.length > 0) {
    console.log(`\n--- External Links (${result.links.external.length}) ---`);
    for (const link of result.links.external.slice(0, 20)) {
      console.log(`  ${link}`);
    }
    if (result.links.external.length > 20) {
      console.log(`  ... and ${result.links.external.length - 20} more`);
    }
  }

  if (includeJs && result.resources.scripts.length > 0) {
    console.log(`\n--- JavaScript Files (${result.resources.scripts.length}) ---`);
    for (const script of result.resources.scripts.slice(0, 15)) {
      console.log(`  ${script}`);
    }
  }

  if (includeForms && result.forms.length > 0) {
    console.log(`\n--- Forms (${result.forms.length}) ---`);
    for (const form of result.forms) {
      console.log(`  [${form.method}] ${form.action}`);
    }
  }

  if (result.emails.length > 0) {
    console.log(`\n--- Email Addresses (${result.emails.length}) ---`);
    for (const email of result.emails) {
      console.log(`  ${email}`);
    }
  }

  if (result.interesting.length > 0) {
    console.log(`\n--- Interesting Paths (${result.interesting.length}) ---`);
    for (const path of result.interesting) {
      console.log(`  ${path}`);
    }
  }

  console.log('\n--- Summary ---');
  console.log(`  Internal: ${result.summary.internal_links} | External: ${result.summary.external_links} | Subdomains: ${result.summary.subdomain_links}`);
  console.log(`  Scripts: ${result.summary.scripts} | Forms: ${result.summary.forms} | Emails: ${result.summary.emails}`);
  console.log('\n' + '='.repeat(60));
}

// Main
extractLinks(url).then(result => {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResults(result);
  }
});
