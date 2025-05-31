import { NextResponse } from 'next/server';
import { rateLimit } from '@/lib/rate-limit';

const limiter = rateLimit({
  interval: 60 * 1000, // 60 seconds
  uniqueTokenPerInterval: 500
});

// Load API key at module level
const API_KEY = process.env.NEXT_PUBLIC_GOOGLE_SAFE_BROWSING_API_KEY;
console.log('Loading API key:', {
  hasKey: !!API_KEY,
  keyLength: API_KEY?.length,
  envKeys: Object.keys(process.env).filter(key => key.includes('GOOGLE'))
});

export async function POST(request: Request) {
  try {
    // Apply rate limiting
    await limiter.check(5, 'CACHE_TOKEN');

    const { url } = await request.json();
    console.log('Checking URL:', url);

    if (!url) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    // Basic URL validation
    try {
      new URL(url);
    } catch {
      return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
    }

    // Google Safe Browsing API check
    if (!API_KEY) {
      console.error('Google Safe Browsing API key is not configured');
      return NextResponse.json({ 
        error: 'API configuration error',
        details: 'Safe Browsing API is not properly configured'
      }, { status: 500 });
    }

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
    console.log('Making request to Google Safe Browsing API...');
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: {
          clientId: 'url-safety-checker',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });

    console.log('Google Safe Browsing API response status:', response.status);

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      console.error('Google Safe Browsing API error:', errorData);
      return NextResponse.json({ 
        error: 'Safe Browsing API error',
        details: errorData?.error?.message || 'Failed to check URL against Safe Browsing API'
      }, { status: response.status });
    }

    const data = await response.json();
    console.log('Google Safe Browsing API response:', data);

    const isSafe = !data.matches || data.matches.length === 0;

    // Additional checks (you can expand these)
    const hasRedFlags = checkForRedFlags(url);
    console.log('URL check results:', {
      isSafe,
      hasRedFlags,
      matches: data.matches || []
    });

    return NextResponse.json({
      safe: isSafe && !hasRedFlags,
      warnings: hasRedFlags ? ['URL contains suspicious patterns'] : [],
      details: {
        googleSafeBrowsing: isSafe ? 'No threats detected' : 'Threats detected',
        suspiciousPatterns: hasRedFlags,
        threats: data.matches || []
      }
    });

  } catch (error) {
    console.error('Error checking URL:', error);
    return NextResponse.json(
      { error: 'Failed to check URL safety' },
      { status: 500 }
    );
  }
}

function checkForRedFlags(url: string): boolean {
  const lowercaseUrl = url.toLowerCase();
  
  // Common phishing indicators
  const redFlags = [
    'login',
    'signin',
    'verify',
    'account',
    'security',
    'update',
    'password'
  ];
  
  // Check for suspicious TLDs
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
  
  // Check for IP addresses instead of domain names
  const ipAddressRegex = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  
  // Check for suspicious characters in domain
  const suspiciousCharsRegex = /[^a-zA-Z0-9-_.]/;

  const checks = {
    hasRedFlag: redFlags.some(flag => lowercaseUrl.includes(flag)),
    hasSuspiciousTld: suspiciousTlds.some(tld => lowercaseUrl.endsWith(tld)),
    isIpAddress: ipAddressRegex.test(lowercaseUrl),
    hasSuspiciousChars: suspiciousCharsRegex.test(new URL(url).hostname)
  };

  console.log('Suspicious pattern checks:', checks);
  
  return Object.values(checks).some(result => result);
} 