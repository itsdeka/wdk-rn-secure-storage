/**
 * Mock for expo-crypto
 * Used in tests to simulate cryptographic operations
 */

export enum CryptoDigestAlgorithm {
  SHA256 = 'SHA256',
  SHA384 = 'SHA384',
  SHA512 = 'SHA512',
}

/**
 * Mock digestStringAsync function
 * Returns a deterministic hash based on input string
 * For testing purposes, uses a simple hash to ensure consistency
 */
export async function digestStringAsync(
  algorithm: CryptoDigestAlgorithm,
  data: string
): Promise<string> {
  // Simple deterministic hash for testing (not cryptographically secure, but consistent)
  let hash = 0
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  
  // Convert to hex string (64 chars for SHA-256)
  const hex = Math.abs(hash).toString(16).padStart(8, '0')
  // Repeat to get 64 characters (SHA-256 length)
  return (hex.repeat(8)).substring(0, 64)
}


