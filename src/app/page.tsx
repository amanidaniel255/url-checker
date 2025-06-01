'use client';

import { useState, useCallback } from 'react';
import { assessRisks } from '@/lib/security/riskAssessment';

interface SecurityAnalysis {
  urlStructure: {
    isValidUrl: boolean;
    protocol: string;
    domain: string;
    tld: string;
    hasSubdomain: boolean;
    pathDepth: number;
    queryParameters: Record<string, string>;
    fragmentPresent: boolean;
  };
  domainAnalysis: {
    isIpAddress: boolean;
    isWellKnownTLD: boolean;
    domainAge?: Date;
    hasValidDNS: boolean;
    dnsRecords?: any;
    isLocalhost: boolean;
    isPrivateIP: boolean;
  };
  securityIndicators: {
    hasSSL: boolean;
    sslDetails?: {
      validFrom: Date;
      validTo: Date;
      issuer: string;
      isValid: boolean;
    };
    suspiciousPatterns: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    warnings: string[];
  };
  phishingIndicators: {
    containsSuspiciousTerms: boolean;
    hasMixedCharacterSet: boolean;
    isSuspiciouslyLong: boolean;
    containsEncodedChars: boolean;
    mimicsPopularDomain: boolean;
    suspiciousTerms: string[];
  };
  contentSecurity: {
    hasXSSPayload: boolean;
    hasSQLInjection: boolean;
    hasCommandInjection: boolean;
    maliciousPatterns: string[];
  };
}

interface CryptoAnalysis {
  certificate: {
    valid: boolean;
    issuer: string;
    subject: string;
    validFrom: Date;
    validTo: Date;
    serialNumber: string;
    fingerprint: string;
    version: number;
    signatureAlgorithm: string;
    keyStrength?: number;
    errors?: string[];
    expiryStatus: 'valid' | 'expired';
    daysUntilExpiry: number;
  };
  protocols: {
    protocols: string[];
    ciphers: Array<{
      name: string;
      version: string;
      strength: 'weak' | 'medium' | 'strong';
    }>;
    tls13Support: boolean;
    securityLevel: 'low' | 'medium' | 'high';
    warnings: string[];
    recommendations: string[];
  };
  overallSecurity: {
    score: number;
    level: 'critical' | 'low' | 'medium' | 'high';
    summary: string;
  };
  recommendations: string[];
}

interface CheckResult {
  safe: boolean;
  warnings: string[];
  analysis: SecurityAnalysis;
}

interface HistoryEntry {
  url: string;
  result: CheckResult;
  timestamp: Date;
}

interface URLAnalysis {
  protocol: string;
  domain: string;
  path: string;
  hasSSL: boolean;
  parameters: Record<string, string>;
  isWellKnownTLD: boolean;
  hasSubdomain: boolean;
  domainLength: number;
}

const WELL_KNOWN_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil',
  'uk', 'ca', 'au', 'de', 'fr', 'jp', 'br', 'it'
]);

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [urlAnalysis, setUrlAnalysis] = useState<URLAnalysis | null>(null);
  const [cryptoAnalysis, setCryptoAnalysis] = useState<CryptoAnalysis | null>(null);
  const [riskAssessment, setRiskAssessment] = useState(null);
  const [copied, setCopied] = useState(false);

  const analyzeURL = useCallback((urlString: string): URLAnalysis => {
    try {
      const parsedUrl = new URL(urlString);
      const parameters: Record<string, string> = {};
      parsedUrl.searchParams.forEach((value, key) => {
        parameters[key] = value;
      });

      const domainParts = parsedUrl.hostname.split('.');
      const tld = domainParts[domainParts.length - 1].toLowerCase();
      const hasSubdomain = domainParts.length > 2;

      return {
        protocol: parsedUrl.protocol,
        domain: parsedUrl.hostname,
        path: parsedUrl.pathname,
        hasSSL: parsedUrl.protocol === 'https:',
        parameters,
        isWellKnownTLD: WELL_KNOWN_TLDS.has(tld),
        hasSubdomain,
        domainLength: parsedUrl.hostname.length
      };
    } catch (e) {
      return {
        protocol: '',
        domain: '',
        path: '',
        hasSSL: false,
        parameters: {},
        isWellKnownTLD: false,
        hasSubdomain: false,
        domainLength: 0
      };
    }
  }, []);

  const checkUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    setUrlAnalysis(null);
    setCryptoAnalysis(null);
    setRiskAssessment(null);
    setCopied(false);

    try {
      const analysis = analyzeURL(url);
      setUrlAnalysis(analysis);

      // Perform security, crypto, and risk analysis in parallel
      const [securityResponse, cryptoResponse] = await Promise.all([
        fetch('/api/check-url', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url }),
        }),
        fetch('/api/crypto-analysis', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url }),
        })
      ]);

      if (!securityResponse.ok || !cryptoResponse.ok) {
        const error = await securityResponse.json();
        throw new Error(error.error || 'Failed to check URL');
      }

      const [securityData, cryptoData] = await Promise.all([
        securityResponse.json(),
        cryptoResponse.json()
      ]);

      setResult(securityData);
      setCryptoAnalysis(cryptoData);
      
      // Perform risk assessment
      const riskData = assessRisks(securityData.analysis);
      setRiskAssessment(riskData);

      setHistory(prev => [{
        url,
        result: securityData,
        timestamp: new Date()
      }, ...prev.slice(0, 4)]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getSecurityScore = useCallback((): number => {
    if (!result || !urlAnalysis) return 0;

    let score = 100;
    
    // Major security issues
    if (!result.safe) score -= 50;
    if (result.warnings.length > 0) score -= 10 * result.warnings.length;
    if (!urlAnalysis.hasSSL) score -= 20;
    if (result.analysis.securityIndicators.suspiciousPatterns.length > 0) score -= 15;
    
    // URL structure analysis
    if (!urlAnalysis.isWellKnownTLD) score -= 5;
    if (urlAnalysis.hasSubdomain && urlAnalysis.domain.includes('login')) score -= 10;
    if (urlAnalysis.domainLength > 30) score -= 5;
    if (Object.keys(urlAnalysis.parameters).length > 5) score -= 5;
    
    return Math.max(0, score);
  }, [result, urlAnalysis]);

  const getSecurityLevel = useCallback((score: number): {
    label: string;
    color: string;
    description: string;
  } => {
    if (score >= 90) {
      return {
        label: 'Very Safe',
        color: 'bg-green-500',
        description: 'This URL appears to be very safe to visit.'
      };
    } else if (score >= 70) {
      return {
        label: 'Generally Safe',
        color: 'bg-green-400',
        description: 'This URL appears to be safe but exercise normal caution.'
      };
    } else if (score >= 50) {
      return {
        label: 'Exercise Caution',
        color: 'bg-yellow-500',
        description: 'Be careful when visiting this URL and avoid sharing sensitive information.'
      };
    } else if (score >= 30) {
      return {
        label: 'Potentially Unsafe',
        color: 'bg-orange-500',
        description: 'This URL has several security concerns. Proceed with extreme caution.'
      };
    } else {
      return {
        label: 'Unsafe',
        color: 'bg-red-500',
        description: 'This URL is likely unsafe. We recommend not visiting this site.'
      };
    }
  }, []);

  const handleShare = async () => {
    try {
      await navigator.share({
        title: 'URL Safety Check Result',
        text: `URL Safety Check for ${url}:
Security Score: ${getSecurityScore()}%
Status: ${result?.safe ? 'Safe' : 'Potentially Unsafe'}
Analysis: ${result?.analysis.securityIndicators.suspiciousPatterns.join(', ')}`,
        url: window.location.href
      });
    } catch (err) {
      handleCopy();
    }
  };

  const handleCopy = () => {
    const securityScore = getSecurityScore();
    const securityLevel = getSecurityLevel(securityScore);
    
    const textToCopy = `URL Safety Check Result:
URL: ${url}
Security Score: ${securityScore}% - ${securityLevel.label}
Status: ${result?.safe ? 'Safe' : 'Potentially Unsafe'}
Protocol: ${urlAnalysis?.protocol || 'N/A'}
SSL/HTTPS: ${urlAnalysis?.hasSSL ? 'Yes' : 'No'}
${result?.analysis.securityIndicators.suspiciousPatterns.join('\n')}`;

    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getThreatDescription = (threatType: string) => {
    const descriptions: Record<string, string> = {
      'MALWARE': 'This URL may contain malicious software that could harm your device.',
      'SOCIAL_ENGINEERING': 'This URL may be trying to trick you into revealing sensitive information.',
      'UNWANTED_SOFTWARE': 'This URL may contain software that can change your browser settings or affect your system.',
      'POTENTIALLY_HARMFUL_APPLICATION': 'This URL may contain applications that can compromise your device security.'
    };
    return descriptions[threatType] || threatType;
  };

  const formatTimestamp = (date: Date) => {
    return new Intl.DateTimeFormat('en-US', {
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric'
    }).format(date);
  };

  const score = getSecurityScore();
  const securityLevel = getSecurityLevel(score);

  const SecurityIndicator = ({ label, value, type }: { label: string; value: boolean; type: 'good' | 'warning' | 'danger' }) => {
    const colors = {
      good: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      warning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      danger: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
    };

    return (
      <div className={`flex items-center justify-between p-2 rounded-lg ${colors[type]}`}>
        <span className="font-medium">{label}</span>
        <span className="ml-2">
          {value ? (
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          )}
        </span>
      </div>
    );
  };

  const SecurityAnalysisPanel = ({ analysis }: { analysis: SecurityAnalysis }) => {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
        <div className="space-y-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-3">URL Structure Analysis</h3>
            <div className="space-y-2">
              <SecurityIndicator 
                label="Valid URL Format" 
                value={analysis.urlStructure.isValidUrl} 
                type="good" 
              />
              <SecurityIndicator 
                label="Uses HTTPS" 
                value={analysis.urlStructure.protocol === 'https:'} 
                type="good" 
              />
              <SecurityIndicator 
                label="Has Subdomain" 
                value={analysis.urlStructure.hasSubdomain} 
                type={analysis.urlStructure.hasSubdomain ? 'warning' : 'good'} 
              />
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-3">Domain Analysis</h3>
            <div className="space-y-2">
              <SecurityIndicator 
                label="Well-known TLD" 
                value={analysis.domainAnalysis.isWellKnownTLD} 
                type="good" 
              />
              <SecurityIndicator 
                label="Valid DNS" 
                value={analysis.domainAnalysis.hasValidDNS} 
                type="good" 
              />
              <SecurityIndicator 
                label="Uses IP Address" 
                value={analysis.domainAnalysis.isIpAddress} 
                type="danger" 
              />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-3">Phishing Detection</h3>
            <div className="space-y-2">
              <SecurityIndicator 
                label="Suspicious Terms" 
                value={!analysis.phishingIndicators.containsSuspiciousTerms} 
                type="warning" 
              />
              <SecurityIndicator 
                label="Mixed Character Sets" 
                value={!analysis.phishingIndicators.hasMixedCharacterSet} 
                type="danger" 
              />
              <SecurityIndicator 
                label="Domain Mimicking" 
                value={!analysis.phishingIndicators.mimicsPopularDomain} 
                type="danger" 
              />
            </div>
            {analysis.phishingIndicators.suspiciousTerms.length > 0 && (
              <div className="mt-3 text-sm text-yellow-600 dark:text-yellow-400">
                Suspicious terms found: {analysis.phishingIndicators.suspiciousTerms.join(', ')}
              </div>
            )}
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-3">Content Security</h3>
            <div className="space-y-2">
              <SecurityIndicator 
                label="XSS Protection" 
                value={!analysis.contentSecurity.hasXSSPayload} 
                type="danger" 
              />
              <SecurityIndicator 
                label="SQL Injection Protection" 
                value={!analysis.contentSecurity.hasSQLInjection} 
                type="danger" 
              />
              <SecurityIndicator 
                label="Command Injection Protection" 
                value={!analysis.contentSecurity.hasCommandInjection} 
                type="danger" 
              />
            </div>
            {analysis.contentSecurity.maliciousPatterns.length > 0 && (
              <div className="mt-3 text-sm text-red-600 dark:text-red-400">
                Detected threats: {analysis.contentSecurity.maliciousPatterns.join(', ')}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      {/* Hero Section */}
      <div className="relative overflow-hidden bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
        <div className="relative max-w-4xl mx-auto py-16 px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl font-extrabold tracking-tight text-gray-900 dark:text-white sm:text-5xl lg:text-6xl">
              Peruzi Salama
            </h1>
            <p className="mt-6 max-w-2xl mx-auto text-xl text-gray-500 dark:text-gray-400">
              Advanced URL Security Analysis powered by AI
            </p>
          </div>

          {/* URL Input Form */}
          <form onSubmit={checkUrl} className="mt-12 sm:mx-auto sm:max-w-3xl">
            <div className="sm:flex">
              <div className="flex-1 min-w-0">
                <label htmlFor="url" className="sr-only">URL to check</label>
                <input
                  type="url"
                  required
                  id="url"
                  className="block w-full px-5 py-4 text-base rounded-lg border border-gray-300 dark:border-gray-600 shadow-sm focus:ring-2 focus:ring-gray-500 focus:border-gray-500 dark:bg-gray-800 dark:text-white dark:focus:ring-gray-400 placeholder-gray-400"
                  placeholder="Enter any URL to check its security (e.g., https://example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <div className="mt-3 sm:mt-0 sm:ml-3">
                <button
                  type="submit"
                  disabled={loading}
                  className="block w-full px-8 py-4 text-base font-medium text-white bg-gray-900 hover:bg-gray-800 dark:bg-gray-700 dark:hover:bg-gray-600 rounded-lg shadow-sm focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 dark:focus:ring-gray-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                >
                  {loading ? (
                    <div className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Analyzing...
                    </div>
                  ) : 'Analyze URL'}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-4xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        {/* Error Message */}
        {error && (
          <div className="mb-8 rounded-lg bg-red-50 dark:bg-red-900/30 p-4 border border-red-200 dark:border-red-800 animate-fade-in">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-red-800 dark:text-red-200">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Analysis Results */}
        {(result || cryptoAnalysis || riskAssessment) && (
          <div className="space-y-6 animate-fade-in">
            {/* Combined Security Scores */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Overall Security Score */}
              {result && (
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden border border-gray-200 dark:border-gray-700">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center">
                        <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        Security
                      </h2>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        result.safe 
                          ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' 
                          : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                      }`}>
                        {result.safe ? 'Safe' : 'Risk Detected'}
                      </span>
                    </div>
                    
                    <div className="mt-4">
                      <div className="relative pt-1">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <span className="text-3xl font-bold text-gray-900 dark:text-white">
                              {getSecurityScore()}%
                            </span>
                          </div>
                          <div className="text-right">
                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                              {getSecurityLevel(getSecurityScore()).label}
                            </div>
                          </div>
                        </div>
                        <div className="overflow-hidden h-2 text-xs flex rounded-full bg-gray-200 dark:bg-gray-700">
                          <div
                            style={{ 
                              width: `${getSecurityScore()}%`,
                              transition: 'width 1s ease-in-out'
                            }}
                            className={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${
                              getSecurityScore() > 80 ? 'bg-green-500' :
                              getSecurityScore() > 60 ? 'bg-yellow-500' :
                              'bg-red-500'
                            }`}
                          />
                        </div>
                        <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">
                          {getSecurityLevel(getSecurityScore()).description}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Crypto Security Score */}
              {cryptoAnalysis && (
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden border border-gray-200 dark:border-gray-700">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center">
                        <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                        Crypto
                      </h2>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        cryptoAnalysis.overallSecurity.level === 'high' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                        cryptoAnalysis.overallSecurity.level === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                      }`}>
                        {cryptoAnalysis.overallSecurity.level.charAt(0).toUpperCase() + cryptoAnalysis.overallSecurity.level.slice(1)}
                      </span>
                    </div>
                    
                    <div className="mt-4">
                      <div className="relative pt-1">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <span className="text-3xl font-bold text-gray-900 dark:text-white">
                              {cryptoAnalysis.overallSecurity.score}%
                            </span>
                          </div>
                        </div>
                        <div className="overflow-hidden h-2 text-xs flex rounded-full bg-gray-200 dark:bg-gray-700">
                          <div
                            style={{ 
                              width: `${cryptoAnalysis.overallSecurity.score}%`,
                              transition: 'width 1s ease-in-out'
                            }}
                            className={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${
                              cryptoAnalysis.overallSecurity.score > 80 ? 'bg-green-500' :
                              cryptoAnalysis.overallSecurity.score > 60 ? 'bg-yellow-500' :
                              'bg-red-500'
                            }`}
                          />
                        </div>
                        <p className="mt-2 text-sm text-gray-600 dark:text-gray-300 line-clamp-2">
                          {cryptoAnalysis.overallSecurity.summary}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Risk Assessment Score */}
              {riskAssessment && (
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden border border-gray-200 dark:border-gray-700">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center">
                        <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        Risk
                      </h2>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        riskAssessment.overallRisk.level === 'low' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                        riskAssessment.overallRisk.level === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        riskAssessment.overallRisk.level === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400' :
                        'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                      }`}>
                        {riskAssessment.overallRisk.level.charAt(0).toUpperCase() + riskAssessment.overallRisk.level.slice(1)}
                      </span>
                    </div>
                    
                    <div className="mt-4">
                      <div className="relative pt-1">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <span className="text-3xl font-bold text-gray-900 dark:text-white">
                              {riskAssessment.overallRisk.score}%
                            </span>
                          </div>
                        </div>
                        <div className="overflow-hidden h-2 text-xs flex rounded-full bg-gray-200 dark:bg-gray-700">
                          <div
                            style={{ 
                              width: `${riskAssessment.overallRisk.score}%`,
                              transition: 'width 1s ease-in-out'
                            }}
                            className={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${
                              riskAssessment.overallRisk.score > 70 ? 'bg-green-500' :
                              riskAssessment.overallRisk.score > 50 ? 'bg-yellow-500' :
                              riskAssessment.overallRisk.score > 30 ? 'bg-orange-500' :
                              'bg-red-500'
                            }`}
                          />
                        </div>
                        <p className="mt-2 text-sm text-gray-600 dark:text-gray-300 line-clamp-2">
                          {riskAssessment.overallRisk.summary}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Crypto Details */}
            {cryptoAnalysis && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Certificate Status */}
                <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                  <div className="p-5">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center mb-4">
                      <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      Certificate
                    </h3>
                    <dl className="space-y-3">
                      <div className="flex justify-between items-center">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">Status</dt>
                        <dd className={`text-sm font-medium px-2 py-1 rounded ${
                          cryptoAnalysis.certificate.valid 
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' 
                            : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        }`}>
                          {cryptoAnalysis.certificate.valid ? 'Valid' : 'Invalid'}
                        </dd>
                      </div>
                      <div className="flex justify-between items-center">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">Expires</dt>
                        <dd className={`text-sm font-medium px-2 py-1 rounded ${
                          cryptoAnalysis.certificate.daysUntilExpiry > 30 
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' 
                            : cryptoAnalysis.certificate.daysUntilExpiry > 0 
                            ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                            : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        }`}>
                          {cryptoAnalysis.certificate.daysUntilExpiry > 0 
                            ? `In ${cryptoAnalysis.certificate.daysUntilExpiry} days`
                            : 'Expired'}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>

                {/* Protocol Security */}
                <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                  <div className="p-5">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center mb-4">
                      <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                      Protocol
                    </h3>
                    <dl className="space-y-3">
                      <div className="flex justify-between items-center">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">TLS Version</dt>
                        <dd className={`text-sm font-medium px-2 py-1 rounded ${
                          cryptoAnalysis.protocols.tls13Support 
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' 
                            : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                        }`}>
                          {cryptoAnalysis.protocols.protocols[0]}
                        </dd>
                      </div>
                      <div className="flex justify-between items-center">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">Security</dt>
                        <dd className={`text-sm font-medium px-2 py-1 rounded ${
                          cryptoAnalysis.protocols.securityLevel === 'high'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                            : cryptoAnalysis.protocols.securityLevel === 'medium'
                            ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                            : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        }`}>
                          {cryptoAnalysis.protocols.securityLevel.charAt(0).toUpperCase() + 
                           cryptoAnalysis.protocols.securityLevel.slice(1)}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>

                {/* Cipher Strength */}
                <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                  <div className="p-5">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center mb-4">
                      <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
                      </svg>
                      Cipher
                    </h3>
                    <dl className="space-y-3">
                      <div className="flex justify-between items-center">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">Strength</dt>
                        <dd className={`text-sm font-medium px-2 py-1 rounded ${
                          cryptoAnalysis.protocols.ciphers[0]?.strength === 'strong'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                            : cryptoAnalysis.protocols.ciphers[0]?.strength === 'medium'
                            ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                            : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        }`}>
                          {cryptoAnalysis.protocols.ciphers[0]?.strength.charAt(0).toUpperCase() +
                           cryptoAnalysis.protocols.ciphers[0]?.strength.slice(1)}
                        </dd>
                      </div>
                      <div className="flex flex-col space-y-1">
                        <dt className="text-sm text-gray-500 dark:text-gray-400">Algorithm</dt>
                        <dd className="text-sm text-gray-900 dark:text-white font-mono bg-gray-50 dark:bg-gray-700/50 px-3 py-2 rounded break-all">
                          {cryptoAnalysis.protocols.ciphers[0]?.name}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>
              </div>
            )}

            {/* Security Recommendations */}
            {cryptoAnalysis?.recommendations.length > 0 && (
              <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                    <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Security Recommendations
                  </h3>
                </div>
                <div className="px-6 py-5">
                  <ul className="space-y-2">
                    {cryptoAnalysis.recommendations.map((recommendation, index) => (
                      <li key={index} className="flex items-start">
                        <svg className="h-5 w-5 text-yellow-500 mr-2 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span className="text-sm text-gray-600 dark:text-gray-300">{recommendation}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Risk Assessment Section */}
            {riskAssessment && (
              <div className="space-y-6">
                {/* Risk Categories */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {Object.entries(riskAssessment.categories).map(([key, category]) => (
                    <div key={key} className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                      <div className="p-5">
                        <div className="flex items-center justify-between mb-4">
                          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                            {category.name}
                          </h3>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                            category.level === 'low' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                            category.level === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                            category.level === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400' :
                            'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                          }`}>
                            {category.score}% Safe
                          </span>
                        </div>
                        <ul className="space-y-2">
                          {category.findings.map((finding, index) => (
                            <li key={index} className="flex items-start text-sm text-gray-600 dark:text-gray-300">
                              <svg className="h-5 w-5 text-yellow-500 mr-2 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                              {finding}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Vulnerabilities */}
                {riskAssessment?.vulnerabilities.length > 0 && (
                  <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                    <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                        <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                        </svg>
                        Detected Vulnerabilities
                      </h3>
                    </div>
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                      {riskAssessment.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="px-6 py-4">
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white flex items-center">
                              <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mr-2 ${
                                vuln.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                                vuln.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400' :
                                'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                              }`}>
                                {vuln.severity.toUpperCase()}
                              </span>
                              {vuln.description}
                            </h4>
                          </div>
                          <div className="space-y-2">
                            <p className="text-sm text-gray-600 dark:text-gray-300">
                              <span className="font-medium">Impact:</span> {vuln.impact}
                            </p>
                            <p className="text-sm text-gray-600 dark:text-gray-300">
                              <span className="font-medium">Mitigation:</span> {vuln.mitigation}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {riskAssessment?.recommendations.length > 0 && (
                  <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                    <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                        <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                        </svg>
                        Security Recommendations
                      </h3>
                    </div>
                    <div className="px-6 py-5">
                      <ul className="space-y-3">
                        {riskAssessment.recommendations.map((recommendation, index) => (
                          <li key={index} className="flex items-start">
                            <svg className="h-5 w-5 text-green-500 mr-2 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span className="text-sm text-gray-600 dark:text-gray-300">{recommendation}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Recent Checks */}
            {history.length > 0 && (
              <div className="bg-white dark:bg-gray-800 overflow-hidden rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                    <svg className="h-5 w-5 mr-2 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Recent Checks
                  </h3>
                </div>
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {history.map((entry, index) => (
                    <div key={index} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors duration-150">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center min-w-0">
                          <span className={`h-2.5 w-2.5 flex-shrink-0 rounded-full ${
                            entry.result.safe ? 'bg-green-500' : 'bg-red-500'
                          }`} aria-hidden="true" />
                          <p className="ml-4 truncate text-sm font-medium text-gray-900 dark:text-white">
                            {entry.url}
                          </p>
                        </div>
                        <div className="ml-4 flex-shrink-0">
                          <p className="text-sm text-gray-500 dark:text-gray-400">
                            {formatTimestamp(entry.timestamp)}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
