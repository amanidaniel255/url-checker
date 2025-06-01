import * as crypto from 'crypto';

export interface SignatureAnalysis {
  isValid: boolean;
  algorithm: string;
  keyType: string;
  keyLength: number;
  strength: 'weak' | 'medium' | 'strong';
  warnings: string[];
  recommendations: string[];
}

export function verifySignature(
  data: string | Buffer,
  signature: string | Buffer,
  publicKey: string | Buffer
): SignatureAnalysis {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    const isValid = verify.verify(publicKey, signature);

    // Extract key information
    const keyObject = crypto.createPublicKey(publicKey);
    const keyDetails = keyObject.asymmetricKeyDetails;

    const analysis: SignatureAnalysis = {
      isValid,
      algorithm: keyDetails?.hashAlgorithm || 'unknown',
      keyType: keyObject.type,
      keyLength: keyDetails?.modulusLength || 0,
      strength: 'weak',
      warnings: [],
      recommendations: []
    };

    // Analyze key strength
    if (keyDetails?.modulusLength) {
      analysis.strength = getKeyStrength(keyDetails.modulusLength);
      const strengthAnalysis = analyzeKeyStrength(keyDetails.modulusLength);
      analysis.warnings = strengthAnalysis.warnings;
      analysis.recommendations = strengthAnalysis.recommendations;
    }

    return analysis;
  } catch (error) {
    return {
      isValid: false,
      algorithm: 'unknown',
      keyType: 'unknown',
      keyLength: 0,
      strength: 'weak',
      warnings: [`Signature verification failed: ${error.message}`],
      recommendations: [
        'Ensure the signature format is correct',
        'Verify the public key is valid',
        'Check if the signature algorithm is supported'
      ]
    };
  }
}

export function generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({ publicKey, privateKey });
        }
      }
    );
  });
}

export function signData(data: string | Buffer, privateKey: string | Buffer): string {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  return sign.sign(privateKey, 'base64');
}

function getKeyStrength(keyLength: number): 'weak' | 'medium' | 'strong' {
  if (keyLength < 2048) return 'weak';
  if (keyLength < 3072) return 'medium';
  return 'strong';
}

function analyzeKeyStrength(keyLength: number): {
  warnings: string[];
  recommendations: string[];
} {
  const warnings: string[] = [];
  const recommendations: string[] = [];

  if (keyLength < 2048) {
    warnings.push('Key length is below recommended minimum (2048 bits)');
    recommendations.push('Upgrade to at least 2048-bit keys');
  } else if (keyLength < 3072) {
    warnings.push('Key length meets minimum requirements but could be stronger');
    recommendations.push('Consider upgrading to 3072-bit or 4096-bit keys for future-proofing');
  } else if (keyLength >= 4096) {
    recommendations.push('Key length provides strong security');
    recommendations.push('Regular key rotation is still recommended');
  }

  // General recommendations
  recommendations.push('Implement proper key management practices');
  recommendations.push('Monitor for cryptographic vulnerabilities');

  return { warnings, recommendations };
}

export function estimateSignatureSecurity(analysis: SignatureAnalysis): {
  securityLevel: 'low' | 'medium' | 'high';
  timeToBreak: string;
  recommendations: string[];
} {
  if (analysis.keyLength < 2048) {
    return {
      securityLevel: 'low',
      timeToBreak: 'Days to weeks with modern hardware',
      recommendations: [
        'Immediately upgrade to stronger keys (≥2048 bits)',
        'Implement regular key rotation',
        'Use modern signature algorithms'
      ]
    };
  }

  if (analysis.keyLength < 3072) {
    return {
      securityLevel: 'medium',
      timeToBreak: 'Years with current technology',
      recommendations: [
        'Plan upgrade to 3072 or 4096-bit keys',
        'Monitor cryptographic standards',
        'Implement perfect forward secrecy'
      ]
    };
  }

  return {
    securityLevel: 'high',
    timeToBreak: 'Decades with current technology',
    recommendations: [
      'Maintain regular key rotation schedule',
      'Keep up with cryptographic standards',
      'Implement quantum-resistant algorithms when available'
    ]
  };
} 