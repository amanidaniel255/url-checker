export interface SecurityAnalysis {
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