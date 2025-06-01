import { NextResponse } from 'next/server';
import { checkCertificate } from '@/lib/crypto/certificateChecker';
import { analyzeProtocols } from '@/lib/crypto/protocolDetector';
import { URL } from 'url';

export async function POST(request: Request) {
  try {
    const { url } = await request.json();

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // Parse the URL to get the hostname
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;

    // Perform cryptographic analysis
    const [certificateAnalysis, protocolAnalysis] = await Promise.all([
      checkCertificate(hostname),
      analyzeProtocols(hostname)
    ]);

    // Combine the results
    const analysis = {
      certificate: {
        ...certificateAnalysis,
        expiryStatus: certificateAnalysis.validTo > new Date() ? 'valid' : 'expired',
        daysUntilExpiry: Math.floor((certificateAnalysis.validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      },
      protocols: protocolAnalysis,
      overallSecurity: calculateOverallSecurity(certificateAnalysis, protocolAnalysis),
      recommendations: [
        ...new Set([
          ...protocolAnalysis.recommendations,
          ...(certificateAnalysis.errors || []).map(error => `Fix certificate error: ${error}`)
        ])
      ]
    };

    return NextResponse.json(analysis);
  } catch (error) {
    console.error('Crypto analysis failed:', error);
    return NextResponse.json(
      { error: 'Failed to analyze cryptographic security' },
      { status: 500 }
    );
  }
}

function calculateOverallSecurity(
  cert: any,
  protocols: any
): {
  score: number;
  level: 'critical' | 'low' | 'medium' | 'high';
  summary: string;
} {
  let score = 100;
  const issues: string[] = [];

  // Certificate checks
  if (!cert.valid) {
    score -= 40;
    issues.push('Invalid certificate');
  }
  if (cert.errors?.length > 0) {
    score -= 20;
    issues.push('Certificate errors detected');
  }
  if (new Date() > cert.validTo) {
    score -= 30;
    issues.push('Certificate expired');
  }

  // Protocol checks
  if (!protocols.tls13Support) {
    score -= 20;
    issues.push('No TLS 1.3 support');
  }
  if (protocols.securityLevel === 'low') {
    score -= 30;
    issues.push('Weak protocols in use');
  }
  if (protocols.warnings.length > 0) {
    score -= 10 * protocols.warnings.length;
    issues.push('Protocol security warnings');
  }

  // Ensure score stays within bounds
  score = Math.max(0, Math.min(100, score));

  // Determine security level
  let level: 'critical' | 'low' | 'medium' | 'high';
  if (score < 30) level = 'critical';
  else if (score < 50) level = 'low';
  else if (score < 80) level = 'medium';
  else level = 'high';

  // Generate summary
  let summary = issues.length > 0
    ? `Security issues found: ${issues.join(', ')}`
    : 'No major security issues detected';

  return { score, level, summary };
} 