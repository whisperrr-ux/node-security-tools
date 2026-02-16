#!/usr/bin/env node
/**
 * tech-detect.js - Web technology fingerprinting tool
 * Author: ByteCreeper (bytecreeper@proton.me)
 * Usage: node tech-detect.js <url> [--json]
 */

const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const url = args.find(a => !a.startsWith('--'));

if (!url) {
  console.error('Usage: node tech-detect.js <url> [--json]');
  process.exit(1);
}

// Technology signatures
const SIGNATURES = {
  servers: {
    'nginx': /nginx/i,
    'Apache': /Apache/i,
    'IIS': /Microsoft-IIS/i,
    'LiteSpeed': /LiteSpeed/i,
    'Cloudflare': /cloudflare/i,
    'Amazon S3': /AmazonS3/i,
    'Caddy': /Caddy/i,
    'gunicorn': /gunicorn/i,
    'Werkzeug': /Werkzeug/i
  },
  frameworks: {
    'Express.js': /X-Powered-By:\s*Express/i,
    'ASP.NET': /X-AspNet-Version|X-Powered-By:\s*ASP\.NET/i,
    'PHP': /X-Powered-By:\s*PHP/i,
    'Django': /csrftoken|django/i,
    'Rails': /X-Runtime|_rails/i,
    'Laravel': /laravel_session/i,
    'Next.js': /__NEXT_DATA__|_next/,
    'Nuxt.js': /__NUXT__|_nuxt/,
    'React': /react|__REACT/i,
    'Vue.js': /vue|__VUE/i,
    'Angular': /ng-app|ng-controller|angular/i
  },
  cms: {
    'WordPress': /wp-content|wp-includes|wordpress/i,
    'Drupal': /drupal|sites\/all/i,
    'Joomla': /joomla|com_content/i,
    'Shopify': /cdn\.shopify|myshopify/i,
    'Magento': /mage\/|Magento/i,
    'Ghost': /ghost\//i,
    'Squarespace': /squarespace/i,
    'Wix': /wix\.com|wixstatic/i
  },
  cdn: {
    'Cloudflare': /cloudflare|cf-ray/i,
    'Fastly': /fastly/i,
    'Akamai': /akamai/i,
    'AWS CloudFront': /cloudfront/i,
    'Vercel': /vercel|x-vercel/i,
    'Netlify': /netlify/i
  },
  security: {
    'Cloudflare WAF': /cf-ray|__cfduid/i,
    'AWS WAF': /awswaf/i,
    'Sucuri': /sucuri/i,
    'Imperva': /incap_ses|visid_incap/i
  },
  analytics: {
    'Google Analytics': /google-analytics|ga\.js|gtag/i,
    'Google Tag Manager': /googletagmanager/i,
    'Facebook Pixel': /facebook.*pixel|fbq/i,
    'Hotjar': /hotjar/i,
    'Mixpanel': /mixpanel/i
  }
};

async function detectTech(targetUrl) {
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const result = {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    detected: {},
    headers: {},
    cookies: [],
    meta: {}
  };

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow'
    });

    result.status = response.status;
    result.finalUrl = response.url;

    // Collect headers
    const headerText = [];
    for (const [key, value] of response.headers) {
      result.headers[key] = value;
      headerText.push(`${key}: ${value}`);
    }
    const headersStr = headerText.join('\n');

    // Get body content
    const body = await response.text();
    const fullContent = headersStr + '\n' + body;

    // Detect server
    const server = response.headers.get('server');
    if (server) {
      result.meta.server = server;
      for (const [tech, pattern] of Object.entries(SIGNATURES.servers)) {
        if (pattern.test(server)) {
          addDetection(result, 'server', tech, server);
        }
      }
    }

    // Check X-Powered-By
    const poweredBy = response.headers.get('x-powered-by');
    if (poweredBy) {
      result.meta.poweredBy = poweredBy;
    }

    // Get cookies
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) {
      result.cookies = setCookie.split(',').map(c => c.split(';')[0].trim());
    }

    // Check all signatures against full content
    for (const [category, sigs] of Object.entries(SIGNATURES)) {
      for (const [tech, pattern] of Object.entries(sigs)) {
        if (pattern.test(fullContent)) {
          addDetection(result, category, tech);
        }
      }
    }

    // Extract meta generator
    const generatorMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
    if (generatorMatch) {
      result.meta.generator = generatorMatch[1];
      addDetection(result, 'cms', generatorMatch[1]);
    }

    // Check for common JS frameworks in script tags
    if (/<script[^>]*src=["'][^"']*react/i.test(body)) addDetection(result, 'frameworks', 'React');
    if (/<script[^>]*src=["'][^"']*vue/i.test(body)) addDetection(result, 'frameworks', 'Vue.js');
    if (/<script[^>]*src=["'][^"']*angular/i.test(body)) addDetection(result, 'frameworks', 'Angular');
    if (/<script[^>]*src=["'][^"']*jquery/i.test(body)) addDetection(result, 'frameworks', 'jQuery');

  } catch (error) {
    result.error = error.message;
  }

  return result;
}

function addDetection(result, category, tech, detail = null) {
  if (!result.detected[category]) {
    result.detected[category] = [];
  }
  const existing = result.detected[category].find(t => t.name === tech);
  if (!existing) {
    result.detected[category].push({ name: tech, detail });
  }
}

function printResults(result) {
  console.log(`\nTechnology Detection: ${result.url}`);
  console.log('='.repeat(60));
  
  if (result.error) {
    console.log(`\nError: ${result.error}`);
    return;
  }

  console.log(`\nStatus: ${result.status}`);
  if (result.finalUrl !== result.url) {
    console.log(`Final URL: ${result.finalUrl}`);
  }

  if (result.meta.server) console.log(`Server: ${result.meta.server}`);
  if (result.meta.poweredBy) console.log(`Powered By: ${result.meta.poweredBy}`);
  if (result.meta.generator) console.log(`Generator: ${result.meta.generator}`);

  console.log('\n--- Detected Technologies ---');
  
  const categories = ['server', 'cdn', 'security', 'cms', 'frameworks', 'analytics'];
  for (const cat of categories) {
    if (result.detected[cat] && result.detected[cat].length > 0) {
      const catName = cat.charAt(0).toUpperCase() + cat.slice(1);
      console.log(`\n${catName}:`);
      for (const tech of result.detected[cat]) {
        console.log(`  - ${tech.name}${tech.detail ? ` (${tech.detail})` : ''}`);
      }
    }
  }

  if (result.cookies.length > 0) {
    console.log(`\nCookies (${result.cookies.length}):`);
    for (const cookie of result.cookies.slice(0, 10)) {
      console.log(`  - ${cookie}`);
    }
    if (result.cookies.length > 10) {
      console.log(`  ... and ${result.cookies.length - 10} more`);
    }
  }

  console.log('\n' + '='.repeat(60));
}

// Main
detectTech(url).then(result => {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResults(result);
  }
});
