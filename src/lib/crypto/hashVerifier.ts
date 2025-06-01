import * as crypto from 'crypto';

export interface HashAnalysis {
  algorithm: string;
  strength: 'weak' | 'medium' | 'strong';
  recommendations: string[];
  alternativeAlgorithms: string[];
}

export function analyzeHash(hash: string): HashAnalysis {
  // Common hash lengths and their corresponding algorithms
  const hashPatterns: Record<number, { algorithms: string[]; strength: 'weak' | 'medium' | 'strong' }> = {
    32: { algorithms: ['MD5'], strength: 'weak' },
    40: { algorithms: ['SHA-1'], strength: 'weak' },
    64: { algorithms: ['SHA-256', 'SHA3-256'], strength: 'strong' },
    96: { algorithms: ['SHA-384', 'SHA3-384'], strength: 'strong' },
    128: { algorithms: ['SHA-512', 'SHA3-512'], strength: 'strong' }
  };

  const hashLength = hash.length;
  const pattern = hashPatterns[hashLength];

  if (!pattern) {
    return {
      algorithm: 'Unknown',
      strength: 'weak',
      recommendations: ['Unable to determine hash algorithm', 'Consider using SHA-256 or stronger'],
      alternativeAlgorithms: ['SHA-256', 'SHA-384', 'SHA-512']
    };
  }

  return {
    algorithm: pattern.algorithms.join(' or '),
    strength: pattern.strength,
    recommendations: getRecommendations(pattern.strength, pattern.algorithms[0]),
    alternativeAlgorithms: getAlternativeAlgorithms(pattern.strength)
  };
}

export function generateHash(data: string, algorithm: string = 'sha256'): string {
  return crypto.createHash(algorithm).update(data).digest('hex');
}

export function compareHashes(hash1: string, hash2: string): boolean {
  return crypto.timingSafeEqual(Buffer.from(hash1), Buffer.from(hash2));
}

function getRecommendations(strength: 'weak' | 'medium' | 'strong', algorithm: string): string[] {
  if (strength === 'weak') {
    return [
      `${algorithm} is considered cryptographically weak`,
      'Upgrade to SHA-256 or stronger for better security',
      'Consider using modern hash algorithms like SHA-3'
    ];
  }
  if (strength === 'medium') {
    return [
      'Consider upgrading to SHA-256 or stronger',
      'Monitor for cryptographic vulnerabilities'
    ];
  }
  return [
    'Current algorithm provides strong security',
    'Regularly review cryptographic standards for updates'
  ];
}

function getAlternativeAlgorithms(currentStrength: 'weak' | 'medium' | 'strong'): string[] {
  if (currentStrength === 'weak') {
    return ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512'];
  }
  if (currentStrength === 'medium') {
    return ['SHA-384', 'SHA-512', 'SHA3-384', 'SHA3-512'];
  }
  return ['Current algorithm is strong'];
}

export function isHashCollisionResistant(algorithm: string): boolean {
  const weakAlgorithms = ['md5', 'sha1'];
  return !weakAlgorithms.includes(algorithm.toLowerCase());
}

export function estimateHashCrackingDifficulty(hash: string): {
  difficulty: 'easy' | 'moderate' | 'hard';
  timeEstimate: string;
  reason: string;
} {
  const length = hash.length;
  
  if (length <= 32) {
    return {
      difficulty: 'easy',
      timeEstimate: 'Hours to days',
      reason: 'Short hash length, vulnerable to rainbow table attacks'
    };
  }
  
  if (length <= 64) {
    return {
      difficulty: 'moderate',
      timeEstimate: 'Months to years',
      reason: 'Medium hash length, requires significant computational resources'
    };
  }
  
  return {
    difficulty: 'hard',
    timeEstimate: 'Years+',
    reason: 'Long hash length, computationally intensive to crack'
  };
} 