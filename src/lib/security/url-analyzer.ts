import { parse as parseUrl } from 'url';
import * as tls from 'tls';
import * as dns from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);
const dnsResolve = promisify(dns.resolve);

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

export class URLAnalyzer {
  private static WELL_KNOWN_TLDS = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'mil',
    'uk', 'ca', 'au', 'de', 'fr', 'jp', 'br', 'it', 'ru', 'ch', 'nl', 'se', 'no', 'es'
  ]);

  private static SUSPICIOUS_TERMS = [
    'login', 'signin', 'account', 'banking', 'verify', 'security', 'update', 'password',
    'confirm', 'verification', 'authenticate', 'wallet', 'crypto', 'bitcoin', 'payment'
  ];

  private static POPULAR_DOMAINS = [
    'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'bank'
  ];

  private static XSS_PATTERNS = [
    '<script>', 'javascript:', 'onerror=', 'onload=', 'eval(', 'document.cookie'
  ];

  private static SQL_INJECTION_PATTERNS = [
    '\'--', 'OR 1=1', 'UNION SELECT', 'DROP TABLE', 'INSERT INTO', 'DELETE FROM'
  ];

  private static COMMAND_INJECTION_PATTERNS = [
    '&&', '||', ';', '|', '`', '$(',
  ];

  public async analyzeURL(url: string): Promise<SecurityAnalysis> {
    const parsedUrl = parseUrl(url);
    const analysis: SecurityAnalysis = {
      urlStructure: await this.analyzeUrlStructure(parsedUrl),
      domainAnalysis: await this.analyzeDomain(parsedUrl.hostname || ''),
      securityIndicators: await this.checkSecurityIndicators(parsedUrl),
      phishingIndicators: this.checkPhishingIndicators(parsedUrl),
      contentSecurity: this.analyzeContentSecurity(url)
    };

    return analysis;
  }

  private async analyzeUrlStructure(parsedUrl: any) {
    const queryParams: Record<string, string> = {};
    if (parsedUrl.query) {
      parsedUrl.query.split('&').forEach((param: string) => {
        const [key, value] = param.split('=');
        if (key) queryParams[key] = value || '';
      });
    }

    return {
      isValidUrl: this.isValidUrl(parsedUrl),
      protocol: parsedUrl.protocol || '',
      domain: parsedUrl.hostname || '',
      tld: this.extractTLD(parsedUrl.hostname || ''),
      hasSubdomain: this.hasSubdomain(parsedUrl.hostname || ''),
      pathDepth: (parsedUrl.pathname || '').split('/').filter(Boolean).length,
      queryParameters: queryParams,
      fragmentPresent: !!parsedUrl.hash
    };
  }

  private async analyzeDomain(domain: string) {
    const isIp = this.isIPAddress(domain);
    let dnsRecords = null;
    let hasValidDNS = false;

    try {
      if (!isIp) {
        dnsRecords = await dnsResolve(domain);
        hasValidDNS = true;
      }
    } catch (error) {
      hasValidDNS = false;
    }

    return {
      isIpAddress: isIp,
      isWellKnownTLD: URLAnalyzer.WELL_KNOWN_TLDS.has(this.extractTLD(domain)),
      hasValidDNS,
      dnsRecords,
      isLocalhost: domain === 'localhost' || domain === '127.0.0.1',
      isPrivateIP: this.isPrivateIP(domain)
    };
  }

  private async checkSecurityIndicators(parsedUrl: any) {
    const warnings: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    const suspiciousPatterns: string[] = [];

    // Check SSL/TLS
    const hasSSL = parsedUrl.protocol === 'https:';
    if (!hasSSL) {
      warnings.push('Connection is not secure (no HTTPS)');
      riskLevel = 'high';
    }

    // Check for suspicious patterns
    if (this.hasSubdomain(parsedUrl.hostname || '')) {
      const subdomains = parsedUrl.hostname.split('.').slice(0, -2);
      for (const subdomain of subdomains) {
        if (URLAnalyzer.SUSPICIOUS_TERMS.some(term => subdomain.includes(term))) {
          suspiciousPatterns.push(`Suspicious subdomain: ${subdomain}`);
          riskLevel = 'high';
        }
      }
    }

    return {
      hasSSL,
      suspiciousPatterns,
      riskLevel,
      warnings
    };
  }

  private checkPhishingIndicators(parsedUrl: any) {
    const domain = parsedUrl.hostname || '';
    const suspiciousTerms: string[] = [];
    
    // Check for suspicious terms
    URLAnalyzer.SUSPICIOUS_TERMS.forEach(term => {
      if (domain.includes(term)) {
        suspiciousTerms.push(term);
      }
    });

    // Check for domain mimicking
    const mimicsPopularDomain = URLAnalyzer.POPULAR_DOMAINS.some(popularDomain => {
      return domain.includes(popularDomain) && !domain.endsWith(`.${popularDomain}.com`);
    });

    return {
      containsSuspiciousTerms: suspiciousTerms.length > 0,
      hasMixedCharacterSet: this.hasMixedCharacterSet(domain),
      isSuspiciouslyLong: domain.length > 50,
      containsEncodedChars: /%[0-9a-f]{2}/i.test(domain),
      mimicsPopularDomain,
      suspiciousTerms
    };
  }

  private analyzeContentSecurity(url: string) {
    const hasXSSPayload = URLAnalyzer.XSS_PATTERNS.some(pattern => 
      url.toLowerCase().includes(pattern.toLowerCase())
    );

    const hasSQLInjection = URLAnalyzer.SQL_INJECTION_PATTERNS.some(pattern =>
      url.toLowerCase().includes(pattern.toLowerCase())
    );

    const hasCommandInjection = URLAnalyzer.COMMAND_INJECTION_PATTERNS.some(pattern =>
      url.includes(pattern)
    );

    const maliciousPatterns = [];
    if (hasXSSPayload) maliciousPatterns.push('XSS payload detected');
    if (hasSQLInjection) maliciousPatterns.push('SQL injection attempt detected');
    if (hasCommandInjection) maliciousPatterns.push('Command injection attempt detected');

    return {
      hasXSSPayload,
      hasSQLInjection,
      hasCommandInjection,
      maliciousPatterns
    };
  }

  private isValidUrl(parsedUrl: any): boolean {
    return !!(parsedUrl.protocol && parsedUrl.hostname);
  }

  private extractTLD(domain: string): string {
    return domain.split('.').slice(-1)[0] || '';
  }

  private hasSubdomain(domain: string): boolean {
    return domain.split('.').length > 2;
  }

  private isIPAddress(domain: string): boolean {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
  }

  private isPrivateIP(ip: string): boolean {
    if (!this.isIPAddress(ip)) return false;
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  }

  private hasMixedCharacterSet(domain: string): boolean {
    const hasLatin = /[a-z]/i.test(domain);
    const hasCyrillic = /[\u0400-\u04FF]/.test(domain);
    const hasGreek = /[\u0370-\u03FF]/.test(domain);
    const hasOtherScripts = /[^\u0000-\u007F]/.test(domain);
    
    return (hasLatin && (hasCyrillic || hasGreek || hasOtherScripts)) ||
           (hasCyrillic && (hasLatin || hasGreek || hasOtherScripts)) ||
           (hasGreek && (hasLatin || hasCyrillic || hasOtherScripts));
  }
} 