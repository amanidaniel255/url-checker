import { NextResponse } from 'next/server';
import { rateLimit } from '@/lib/rate-limit';
import { URLAnalyzer } from '@/lib/security/url-analyzer';

const limiter = rateLimit({
  interval: 60 * 1000, // 60 seconds
  uniqueTokenPerInterval: 500
});

// Load API key at module level
const API_KEY = process.env.NEXT_PUBLIC_GOOGLE_SAFE_BROWSING_API_KEY;
const urlAnalyzer = new URLAnalyzer();
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

    // Perform enhanced security analysis
    const securityAnalysis = await urlAnalyzer.analyzeURL(url);

    // Google Safe Browsing API check
    let googleSafeBrowsingResult = { matches: [] };
    if (API_KEY) {
      try {
        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
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

        if (response.ok) {
          googleSafeBrowsingResult = await response.json();
        }
      } catch (error) {
        console.error('Google Safe Browsing API error:', error);
      }
    }

    // Combine all security checks
    const isSafe = securityAnalysis.securityIndicators.riskLevel === 'low' && 
                  !googleSafeBrowsingResult.matches?.length &&
                  !securityAnalysis.phishingIndicators.containsSuspiciousTerms &&
                  !securityAnalysis.contentSecurity.maliciousPatterns.length;

    // Compile warnings
    const warnings = [
      ...securityAnalysis.securityIndicators.warnings,
      ...securityAnalysis.contentSecurity.maliciousPatterns
    ];

    if (googleSafeBrowsingResult.matches?.length) {
      warnings.push('Google Safe Browsing detected this URL as potentially harmful');
      googleSafeBrowsingResult.matches.forEach((match: any) => {
        warnings.push(`Threat type: ${match.threatType}`);
      });
    }

    if (securityAnalysis.phishingIndicators.containsSuspiciousTerms) {
      warnings.push('URL contains suspicious terms commonly used in phishing attacks');
    }

    return NextResponse.json({
      safe: isSafe,
      warnings,
      analysis: {
        urlStructure: securityAnalysis.urlStructure,
        domainAnalysis: securityAnalysis.domainAnalysis,
        securityIndicators: securityAnalysis.securityIndicators,
        phishingIndicators: securityAnalysis.phishingIndicators,
        contentSecurity: securityAnalysis.contentSecurity,
        googleSafeBrowsing: googleSafeBrowsingResult.matches || []
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