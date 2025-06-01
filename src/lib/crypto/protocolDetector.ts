import * as tls from 'tls';
import * as https from 'https';

interface ProtocolAnalysis {
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
}

export async function analyzeProtocols(hostname: string): Promise<ProtocolAnalysis> {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({
        host: hostname,
        port: 443,
        rejectUnauthorized: false,
      }, () => {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const warnings: string[] = [];
        const recommendations: string[] = [];

        // Check TLS version
        const isTLS13 = protocol === 'TLSv1.3';
        if (!isTLS13) {
          warnings.push(`Using older protocol: ${protocol}`);
          recommendations.push('Upgrade to TLS 1.3 for better security');
        }

        // Analyze cipher strength
        const cipherStrength = analyzeCipherStrength(cipher.name);
        if (cipherStrength === 'weak') {
          warnings.push('Weak cipher in use');
          recommendations.push('Configure server to use stronger ciphers');
        }

        const result: ProtocolAnalysis = {
          protocols: [protocol],
          ciphers: [{
            name: cipher.name,
            version: cipher.version,
            strength: cipherStrength
          }],
          tls13Support: isTLS13,
          securityLevel: determineSecurityLevel(protocol, cipherStrength),
          warnings,
          recommendations
        };

        socket.end();
        resolve(result);
      });

      socket.on('error', () => {
        // If connection fails, return a default analysis indicating potential issues
        resolve({
          protocols: ['Unknown'],
          ciphers: [{
            name: 'Unknown',
            version: 'Unknown',
            strength: 'weak'
          }],
          tls13Support: false,
          securityLevel: 'low',
          warnings: ['Failed to establish secure connection'],
          recommendations: ['Verify SSL/TLS configuration on the server']
        });
      });
    } catch (error) {
      // Handle any unexpected errors
      resolve({
        protocols: ['Error'],
        ciphers: [{
          name: 'Error',
          version: 'Error',
          strength: 'weak'
        }],
        tls13Support: false,
        securityLevel: 'low',
        warnings: ['Error analyzing protocols'],
        recommendations: ['Verify server configuration and try again']
      });
    }
  });
}

function analyzeCipherStrength(cipherName: string): 'weak' | 'medium' | 'strong' {
  const cipherLower = cipherName.toLowerCase();
  
  // Weak ciphers
  if (
    cipherLower.includes('null') ||
    cipherLower.includes('anon') ||
    cipherLower.includes('export') ||
    cipherLower.includes('des') ||
    cipherLower.includes('rc4') ||
    cipherLower.includes('md5')
  ) {
    return 'weak';
  }

  // Strong ciphers
  if (
    cipherLower.includes('aes-256') ||
    cipherLower.includes('chacha20') ||
    cipherLower.includes('gcm') ||
    cipherLower.includes('poly1305')
  ) {
    return 'strong';
  }

  // Everything else is considered medium
  return 'medium';
}

function determineSecurityLevel(
  protocol: string,
  cipherStrength: 'weak' | 'medium' | 'strong'
): 'low' | 'medium' | 'high' {
  if (protocol === 'TLSv1.3' && cipherStrength === 'strong') {
    return 'high';
  }

  if (
    (protocol === 'TLSv1.2' && cipherStrength !== 'weak') ||
    (protocol === 'TLSv1.3' && cipherStrength === 'medium')
  ) {
    return 'medium';
  }

  return 'low';
}

export function getRecommendedCiphers(): string[] {
  return [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305'
  ];
}

export function getProtocolSecurityInfo(protocol: string): {
  secure: boolean;
  description: string;
  recommendations: string[];
} {
  switch (protocol) {
    case 'TLSv1.3':
      return {
        secure: true,
        description: 'Latest TLS version with improved security and performance',
        recommendations: ['Maintain regular security updates']
      };
    case 'TLSv1.2':
      return {
        secure: true,
        description: 'Secure but not the latest version',
        recommendations: ['Plan upgrade to TLS 1.3', 'Use strong cipher suites']
      };
    case 'TLSv1.1':
      return {
        secure: false,
        description: 'Deprecated and considered insecure',
        recommendations: ['Upgrade to TLS 1.2 or 1.3 immediately']
      };
    case 'TLSv1.0':
    case 'SSLv3':
    case 'SSLv2':
      return {
        secure: false,
        description: 'Critically insecure - multiple known vulnerabilities',
        recommendations: [
          'Upgrade to TLS 1.2 or 1.3 immediately',
          'Disable all SSL versions',
          'Update security configurations'
        ]
      };
    default:
      return {
        secure: false,
        description: 'Unknown or unsupported protocol',
        recommendations: ['Implement TLS 1.2 or 1.3', 'Review security configurations']
      };
  }
} 