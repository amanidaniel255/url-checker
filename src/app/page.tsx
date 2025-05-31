'use client';

import { useState, useCallback } from 'react';

interface CheckResult {
  safe: boolean;
  warnings: string[];
  details: {
    googleSafeBrowsing: string;
    suspiciousPatterns: boolean;
    threats: Array<{
      threatType: string;
      platformType: string;
      threatEntryType: string;
      cacheDuration: string;
    }>;
  };
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
    setCopied(false);

    try {
      const analysis = analyzeURL(url);
      setUrlAnalysis(analysis);
      const response = await fetch('/api/check-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to check URL');
      }

      const data = await response.json();
      setResult(data);
      setHistory(prev => [{
        url,
        result: data,
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
    if (result.details.suspiciousPatterns) score -= 15;
    
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
Analysis: ${result?.details.googleSafeBrowsing}`,
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
${result?.details.googleSafeBrowsing}
${result?.warnings.join('\n')}`;

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

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
            Peruzi Salama
          </h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            Advanced URL Security Analysis
          </p>
        </div>

        <form onSubmit={checkUrl} className="mb-8">
          <div className="flex flex-col sm:flex-row gap-4">
            <input
              type="url"
              required
              className="flex-1 appearance-none rounded-lg px-4 py-3 border border-gray-300 dark:border-gray-600 placeholder-gray-500 text-gray-900 dark:text-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
              placeholder="Enter any URL to check its security (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <button
              type="submit"
              disabled={loading}
              className="inline-flex justify-center items-center px-6 py-3 border border-transparent text-sm font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
            >
              {loading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Checking...
                </>
              ) : 'Check URL'}
            </button>
          </div>
        </form>

        {error && (
          <div className="mb-8 bg-red-50 dark:bg-red-900/50 border-l-4 border-red-400 p-4 rounded-r-lg">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-700 dark:text-red-200">{error}</p>
              </div>
            </div>
          </div>
        )}

        {result && urlAnalysis && (
          <div className={`mb-8 ${result.safe ? 'bg-green-50 dark:bg-green-900/50' : 'bg-red-50 dark:bg-red-900/50'} rounded-lg p-6 shadow-sm`}>
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center">
                {result.safe ? (
                  <svg className="h-8 w-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                ) : (
                  <svg className="h-8 w-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                )}
                <div className="ml-3">
                  <h3 className={`text-xl font-medium ${result.safe ? 'text-green-800 dark:text-green-200' : 'text-red-800 dark:text-red-200'}`}>
                    {securityLevel.label}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                    {securityLevel.description}
                  </p>
                </div>
        </div>
              <div className="flex gap-2">
                <button
                  onClick={handleShare}
                  className="inline-flex items-center px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200"
                >
                  <svg className="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                  </svg>
                  Share
                </button>
                <button
                  onClick={handleCopy}
                  className="inline-flex items-center px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200"
                >
                  {copied ? (
                    <svg className="h-4 w-4 mr-1 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                    </svg>
                  )}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-4">
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Security Score</h4>
                  <div className="flex items-center">
                    <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-4">
                      <div
                        className={`h-4 rounded-full ${securityLevel.color}`}
                        style={{ width: `${score}%` }}
                      ></div>
                    </div>
                    <span className="ml-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                      {score}%
                    </span>
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">URL Analysis</h4>
                  <div className="space-y-2 text-sm text-gray-600 dark:text-gray-300">
                    <div className="flex items-center justify-between">
                      <span>Protocol:</span>
                      <span className={`font-mono ${urlAnalysis.hasSSL ? 'text-green-500' : 'text-yellow-500'}`}>
                        {urlAnalysis.protocol}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Domain:</span>
                      <span className="font-mono">{urlAnalysis.domain}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Path:</span>
                      <span className="font-mono truncate max-w-[200px]">{urlAnalysis.path || '/'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Parameters:</span>
                      <span className="font-mono">{Object.keys(urlAnalysis.parameters).length}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>TLD Type:</span>
                      <span className={`font-mono ${urlAnalysis.isWellKnownTLD ? 'text-green-500' : 'text-yellow-500'}`}>
                        {urlAnalysis.isWellKnownTLD ? 'Well-known' : 'Uncommon'}
                      </span>
                    </div>
                    {urlAnalysis.hasSubdomain && (
                      <div className="flex items-center justify-between">
                        <span>Subdomain:</span>
                        <span className="font-mono text-yellow-500">Present</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Security Analysis</h4>
                  <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-300">
                    <li className="flex items-center">
                      <span className={`w-2 h-2 rounded-full mr-2 ${result.details.googleSafeBrowsing === 'No threats detected' ? 'bg-green-400' : 'bg-red-400'}`}></span>
                      Google Safe Browsing: {result.details.googleSafeBrowsing}
                    </li>
                    <li className="flex items-center">
                      <span className={`w-2 h-2 rounded-full mr-2 ${urlAnalysis.hasSSL ? 'bg-green-400' : 'bg-yellow-400'}`}></span>
                      SSL Security: {urlAnalysis.hasSSL ? 'Secure Connection' : 'Not Secure'}
                    </li>
                    {result.details.suspiciousPatterns && (
                      <li className="flex items-center">
                        <span className="w-2 h-2 rounded-full mr-2 bg-yellow-400"></span>
                        Suspicious patterns detected
                      </li>
                    )}
                  </ul>
                </div>

                {result.details.threats.length > 0 && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Detected Threats</h4>
                    <ul className="space-y-2">
                      {result.details.threats.map((threat, index) => (
                        <li key={index} className="text-sm text-gray-600 dark:text-gray-300">
                          <p className="font-medium text-red-600 dark:text-red-400">{threat.threatType}</p>
                          <p className="ml-4 text-sm">{getThreatDescription(threat.threatType)}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.warnings.length > 0 && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Warnings</h4>
                    <ul className="space-y-1">
                      {result.warnings.map((warning, index) => (
                        <li key={index} className="text-sm text-yellow-600 dark:text-yellow-400">• {warning}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-4 bg-white dark:bg-gray-800 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Security Tips</h4>
              <ul className="space-y-1 text-sm text-gray-600 dark:text-gray-300">
                <li>• Always verify the URL matches the official website you're trying to visit</li>
                <li>• Look for HTTPS in the URL, especially when sharing sensitive information</li>
                <li>• Be cautious of URLs containing numbers instead of website names</li>
                <li>• Watch out for slight misspellings of well-known websites</li>
                {!urlAnalysis.hasSSL && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    • This URL uses HTTP instead of HTTPS - be extra cautious with any sensitive information
                  </li>
                )}
                {urlAnalysis.hasSubdomain && urlAnalysis.domain.includes('login') && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    • This URL contains 'login' in a subdomain - be extra vigilant for phishing attempts
                  </li>
                )}
                {!urlAnalysis.isWellKnownTLD && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    • This URL uses an uncommon top-level domain - verify the website's legitimacy
                  </li>
                )}
              </ul>
            </div>
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm">
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Recent Checks</h3>
            <div className="space-y-3">
              {history.map((entry, index) => (
                <div
                  key={index}
                  className={`p-3 rounded-lg ${
                    entry.result.safe
                      ? 'bg-green-50 dark:bg-green-900/30'
                      : 'bg-red-50 dark:bg-red-900/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      <span
                        className={`w-2 h-2 rounded-full mr-2 ${
                          entry.result.safe ? 'bg-green-400' : 'bg-red-400'
                        }`}
                      ></span>
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate max-w-md">
                        {entry.url}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {formatTimestamp(entry.timestamp)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
