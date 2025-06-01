import * as tls from 'tls';
import * as https from 'https';

interface CertificateInfo {
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
}

export async function checkCertificate(hostname: string): Promise<CertificateInfo> {
  return new Promise((resolve) => {
    const options = {
      host: hostname,
      port: 443,
      method: 'GET',
      rejectUnauthorized: false, // We want to check invalid certs too
    };

    const req = https.request(options, (res) => {
      try {
        const cert = res.socket.getPeerCertificate(true);
        const errors: string[] = [];

        // Check if we got a valid certificate
        if (!cert || Object.keys(cert).length === 0) {
          resolve({
            valid: false,
            issuer: 'Unknown',
            subject: hostname,
            validFrom: new Date(),
            validTo: new Date(),
            serialNumber: 'Unknown',
            fingerprint: 'Unknown',
            version: 1,
            signatureAlgorithm: 'Unknown',
            errors: ['No certificate information available']
          });
          return;
        }

        // Check certificate validity
        const now = new Date();
        const validFrom = new Date(cert.valid_from || Date.now());
        const validTo = new Date(cert.valid_to || Date.now());
        
        if (now < validFrom) {
          errors.push('Certificate not yet valid');
        }
        if (now > validTo) {
          errors.push('Certificate has expired');
        }

        // Check if it's a self-signed certificate
        if (cert.issuerCertificate === cert) {
          errors.push('Self-signed certificate');
        }

        // Safely extract issuer and subject information
        const getIssuerString = (cert: any): string => {
          if (!cert.issuer) return 'Unknown';
          const issuer = cert.issuer;
          return issuer.CN || issuer.O || issuer.OU || 
                 Object.values(issuer).filter(v => typeof v === 'string')[0] || 
                 'Unknown';
        };

        const getSubjectString = (cert: any): string => {
          if (!cert.subject) return hostname;
          const subject = cert.subject;
          return subject.CN || subject.O || subject.OU || 
                 Object.values(subject).filter(v => typeof v === 'string')[0] || 
                 hostname;
        };

        const result: CertificateInfo = {
          valid: errors.length === 0,
          issuer: getIssuerString(cert),
          subject: getSubjectString(cert),
          validFrom,
          validTo,
          serialNumber: cert.serialNumber || 'Unknown',
          fingerprint: cert.fingerprint || 'Unknown',
          version: cert.version || 1,
          signatureAlgorithm: cert.signatureAlgorithm || 'Unknown',
          keyStrength: cert.bits,
          errors: errors.length > 0 ? errors : undefined
        };

        resolve(result);
      } catch (error) {
        // Handle any unexpected errors during certificate processing
        resolve({
          valid: false,
          issuer: 'Unknown',
          subject: hostname,
          validFrom: new Date(),
          validTo: new Date(),
          serialNumber: 'Unknown',
          fingerprint: 'Unknown',
          version: 1,
          signatureAlgorithm: 'Unknown',
          errors: [(error as Error).message]
        });
      }
    });

    req.on('error', (error) => {
      resolve({
        valid: false,
        issuer: 'Unknown',
        subject: hostname,
        validFrom: new Date(),
        validTo: new Date(),
        serialNumber: 'Unknown',
        fingerprint: 'Unknown',
        version: 1,
        signatureAlgorithm: 'Unknown',
        errors: [error.message]
      });
    });

    // Set a timeout to prevent hanging
    req.setTimeout(10000, () => {
      req.destroy();
      resolve({
        valid: false,
        issuer: 'Unknown',
        subject: hostname,
        validFrom: new Date(),
        validTo: new Date(),
        serialNumber: 'Unknown',
        fingerprint: 'Unknown',
        version: 1,
        signatureAlgorithm: 'Unknown',
        errors: ['Connection timeout']
      });
    });

    req.end();
  });
}

export function isCertificateExpiringSoon(validTo: Date, warningDays: number = 30): boolean {
  const now = new Date();
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  return daysUntilExpiry <= warningDays;
}

export function validateCertificateStrength(details: CertificateInfo): {
  isStrong: boolean;
  warnings: string[];
} {
  const warnings: string[] = [];
  let isStrong = true;

  // Check key strength
  if (details.keyStrength) {
    if (details.keyStrength < 2048) {
      warnings.push(`Weak key strength: ${details.keyStrength} bits (recommended: ≥2048 bits)`);
      isStrong = false;
    }
  }

  // Check signature algorithm
  const weakSignatureAlgorithms = ['md5', 'sha1'];
  const sigAlgLower = details.signatureAlgorithm.toLowerCase();
  if (weakSignatureAlgorithms.some(alg => sigAlgLower.includes(alg))) {
    warnings.push(`Weak signature algorithm: ${details.signatureAlgorithm}`);
    isStrong = false;
  }

  // Check certificate validity
  if (!details.valid) {
    warnings.push('Certificate validation failed');
    isStrong = false;
  }

  // Check expiration
  if (isCertificateExpiringSoon(details.validTo)) {
    warnings.push(`Certificate is expiring soon (Valid until: ${details.validTo.toLocaleDateString()})`);
  }

  return { isStrong, warnings };
} 