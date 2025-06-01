import { SecurityAnalysis } from '@/types/security';

export interface RiskAssessment {
  overallRisk: {
    score: number;
    level: 'critical' | 'high' | 'medium' | 'low';
    summary: string;
  };
  categories: {
    domain: RiskCategory;
    ssl: RiskCategory;
    content: RiskCategory;
    reputation: RiskCategory;
  };
  vulnerabilities: Vulnerability[];
  recommendations: string[];
}

interface RiskCategory {
  name: string;
  score: number;
  level: 'critical' | 'high' | 'medium' | 'low';
  findings: string[];
}

interface Vulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  impact: string;
  mitigation: string;
}

export function assessRisks(analysis: SecurityAnalysis): RiskAssessment {
  // Initialize risk categories
  const domainRisks = assessDomainRisks(analysis);
  const sslRisks = assessSSLRisks(analysis);
  const contentRisks = assessContentRisks(analysis);
  const reputationRisks = assessReputationRisks(analysis);

  // Calculate overall risk score
  const overallScore = calculateOverallRiskScore([
    domainRisks,
    sslRisks,
    contentRisks,
    reputationRisks
  ]);

  // Generate vulnerabilities list
  const vulnerabilities = generateVulnerabilities(analysis);

  // Generate recommendations
  const recommendations = generateRecommendations(analysis);

  return {
    overallRisk: {
      score: overallScore,
      level: getRiskLevel(overallScore),
      summary: generateRiskSummary(overallScore, vulnerabilities)
    },
    categories: {
      domain: domainRisks,
      ssl: sslRisks,
      content: contentRisks,
      reputation: reputationRisks
    },
    vulnerabilities,
    recommendations
  };
}

function assessDomainRisks(analysis: SecurityAnalysis): RiskCategory {
  const findings: string[] = [];
  let score = 100;

  // Check domain age
  if (!analysis.domainAnalysis.domainAge) {
    score -= 20;
    findings.push('Domain age information unavailable');
  }

  // Check for suspicious TLD
  if (!analysis.domainAnalysis.isWellKnownTLD) {
    score -= 15;
    findings.push('Uncommon or suspicious TLD detected');
  }

  // Check for IP address usage
  if (analysis.domainAnalysis.isIpAddress) {
    score -= 25;
    findings.push('IP address used instead of domain name');
  }

  // Check for private IP
  if (analysis.domainAnalysis.isPrivateIP) {
    score -= 30;
    findings.push('Private IP address detected');
  }

  return {
    name: 'Domain Security',
    score: Math.max(0, score),
    level: getRiskLevel(score),
    findings
  };
}

function assessSSLRisks(analysis: SecurityAnalysis): RiskCategory {
  const findings: string[] = [];
  let score = 100;

  if (!analysis.securityIndicators.hasSSL) {
    score -= 40;
    findings.push('No SSL/TLS encryption');
  }

  if (analysis.securityIndicators.sslDetails) {
    const { sslDetails } = analysis.securityIndicators;
    
    if (!sslDetails.isValid) {
      score -= 30;
      findings.push('Invalid SSL certificate');
    }

    if (new Date() > new Date(sslDetails.validTo)) {
      score -= 35;
      findings.push('Expired SSL certificate');
    }
  }

  return {
    name: 'SSL/TLS Security',
    score: Math.max(0, score),
    level: getRiskLevel(score),
    findings
  };
}

function assessContentRisks(analysis: SecurityAnalysis): RiskCategory {
  const findings: string[] = [];
  let score = 100;

  if (analysis.contentSecurity.hasXSSPayload) {
    score -= 35;
    findings.push('Cross-site scripting (XSS) vulnerabilities detected');
  }

  if (analysis.contentSecurity.hasSQLInjection) {
    score -= 40;
    findings.push('SQL injection vulnerabilities detected');
  }

  if (analysis.contentSecurity.hasCommandInjection) {
    score -= 45;
    findings.push('Command injection vulnerabilities detected');
  }

  if (analysis.contentSecurity.maliciousPatterns.length > 0) {
    score -= 25;
    findings.push('Malicious patterns detected in content');
  }

  return {
    name: 'Content Security',
    score: Math.max(0, score),
    level: getRiskLevel(score),
    findings
  };
}

function assessReputationRisks(analysis: SecurityAnalysis): RiskCategory {
  const findings: string[] = [];
  let score = 100;

  if (analysis.phishingIndicators.containsSuspiciousTerms) {
    score -= 25;
    findings.push('Suspicious terms detected');
  }

  if (analysis.phishingIndicators.hasMixedCharacterSet) {
    score -= 30;
    findings.push('Mixed character sets detected (potential homograph attack)');
  }

  if (analysis.phishingIndicators.mimicsPopularDomain) {
    score -= 35;
    findings.push('Domain appears to mimic a popular website');
  }

  if (analysis.phishingIndicators.isSuspiciouslyLong) {
    score -= 15;
    findings.push('Suspiciously long URL detected');
  }

  return {
    name: 'Reputation & Phishing',
    score: Math.max(0, score),
    level: getRiskLevel(score),
    findings
  };
}

function calculateOverallRiskScore(categories: RiskCategory[]): number {
  const weights = {
    'Domain Security': 0.25,
    'SSL/TLS Security': 0.30,
    'Content Security': 0.25,
    'Reputation & Phishing': 0.20
  };

  return Math.round(
    categories.reduce((total, category) => {
      return total + (category.score * weights[category.name as keyof typeof weights]);
    }, 0)
  );
}

function getRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score < 30) return 'critical';
  if (score < 50) return 'high';
  if (score < 70) return 'medium';
  return 'low';
}

function generateVulnerabilities(analysis: SecurityAnalysis): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  // Add vulnerabilities based on analysis
  if (analysis.contentSecurity.hasXSSPayload) {
    vulnerabilities.push({
      severity: 'high',
      description: 'Cross-site Scripting (XSS) Vulnerability',
      impact: 'Attackers can inject malicious scripts into web pages viewed by users',
      mitigation: 'Implement proper input validation and output encoding'
    });
  }

  if (analysis.contentSecurity.hasSQLInjection) {
    vulnerabilities.push({
      severity: 'critical',
      description: 'SQL Injection Vulnerability',
      impact: 'Attackers can manipulate database queries to access or modify data',
      mitigation: 'Use parameterized queries and input validation'
    });
  }

  if (!analysis.securityIndicators.hasSSL) {
    vulnerabilities.push({
      severity: 'high',
      description: 'Missing SSL/TLS Encryption',
      impact: 'Data transmitted between client and server is not encrypted',
      mitigation: 'Install and configure SSL/TLS certificate'
    });
  }

  return vulnerabilities;
}

function generateRecommendations(analysis: SecurityAnalysis): string[] {
  const recommendations: string[] = [];

  // Add specific recommendations based on findings
  if (!analysis.securityIndicators.hasSSL) {
    recommendations.push('Implement SSL/TLS encryption');
  }

  if (analysis.phishingIndicators.containsSuspiciousTerms) {
    recommendations.push('Review and modify suspicious content');
  }

  if (analysis.contentSecurity.hasXSSPayload || 
      analysis.contentSecurity.hasSQLInjection || 
      analysis.contentSecurity.hasCommandInjection) {
    recommendations.push('Implement comprehensive input validation');
    recommendations.push('Use security headers (CSP, X-XSS-Protection)');
  }

  return recommendations;
}

function generateRiskSummary(score: number, vulnerabilities: Vulnerability[]): string {
  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'high').length;

  if (score < 30) {
    return `Critical risk level with ${criticalCount} critical and ${highCount} high-severity vulnerabilities`;
  } else if (score < 50) {
    return `High risk level with ${criticalCount} critical and ${highCount} high-severity issues`;
  } else if (score < 70) {
    return `Medium risk level with some security concerns identified`;
  } else {
    return `Low risk level with minimal security concerns`;
  }
} 