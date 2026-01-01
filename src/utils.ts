// External packages
import * as Crypto from 'expo-crypto'

// Internal modules
import { MIN_TIMEOUT_MS, MAX_TIMEOUT_MS } from './constants'
import { TimeoutError, ValidationError } from './errors'
import { validateIdentifier } from './validation'

/**
 * Type for keychain credentials returned by react-native-keychain
 */
export type KeychainCredentials = {
  username: string
  password: string
  service: string
  storage?: string
}

/**
 * Type guard to check if a value is valid keychain credentials
 * 
 * @param value - The value to check
 * @returns true if value is valid keychain credentials with non-empty password
 */
export function isKeychainCredentials(value: unknown): value is KeychainCredentials {
  if (
    value === false ||
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return false
  }

  const obj = value as Record<string, unknown>
  return (
    typeof obj.password === 'string' &&
    obj.password.length > 0 &&
    typeof obj.username === 'string' &&
    typeof obj.service === 'string' &&
    (obj.storage === undefined || typeof obj.storage === 'string')
  )
}

/**
 * Hash identifier using SHA-256 from expo-crypto
 * 
 * @param str - Input string to hash
 * @returns Promise that resolves to a 64-character hexadecimal SHA-256 hash
 */
async function hashIdentifier(str: string): Promise<string> {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, str)
}

/**
 * Valid storage key names
 * These are the only allowed base keys for secure storage
 */
export const VALID_STORAGE_KEYS = [
  'wallet_encryption_key',
  'wallet_encrypted_seed',
  'wallet_encrypted_entropy',
] as const

/**
 * Type-safe storage key names
 * Union type of valid storage keys
 */
export type StorageKey = (typeof VALID_STORAGE_KEYS)[number]

/**
 * Runtime validation for storage keys
 * Ensures only valid base keys are used at runtime
 * 
 * @param key - The key to validate
 * @throws {ValidationError} If the key is not a valid storage key
 * @internal
 */
function assertValidStorageKey(key: string): asserts key is StorageKey {
  const validKey = VALID_STORAGE_KEYS.find((k) => k === key)
  if (!validKey) {
    throw new ValidationError(
      `Invalid storage key: ${key}. Valid keys are: ${VALID_STORAGE_KEYS.join(', ')}`
    )
  }
}

/**
 * Create a StorageKey from a string with runtime validation
 * 
 * @param key - The key string to convert to StorageKey
 * @returns The validated StorageKey
 * @throws {ValidationError} If the key is not a valid storage key
 */
export function createStorageKey(key: string): StorageKey {
  assertValidStorageKey(key)
  // After validation, we know key is one of VALID_STORAGE_KEYS
  return key
}

/**
 * Generate a secure storage key from base key and optional identifier
 * 
 * @param baseKey - The base storage key (must be a valid StorageKey)
 * @param identifier - Optional identifier (e.g., email) to support multiple wallets
 * @returns Promise that resolves to the storage key
 * @throws {ValidationError} If baseKey is not a valid storage key
 */
export async function getStorageKey(baseKey: StorageKey, identifier?: string): Promise<string> {
  // Runtime validation for type system bypasses (e.g., 'invalid_key' as any)
  assertValidStorageKey(baseKey)

  // Handle undefined/null early
  if (identifier == null) {
    return baseKey
  }

  // Validate identifier first (this will throw for empty strings and invalid formats)
  validateIdentifier(identifier)

  // Normalize: lowercase and trim (validation ensures it's not empty after trim)
  const normalized = identifier.toLowerCase().trim()

  // Use SHA-256 hash from expo-crypto to prevent collisions and ensure safe key format
  // This is a battle-tested, production-ready solution
  const hash = await hashIdentifier(normalized)

  return `${baseKey}_${hash}`
}


/**
 * Create a timeout wrapper for promises
 * 
 * **IMPORTANT:** Uses Promise.race() which does NOT cancel the underlying promise.
 * The original promise continues executing after timeout (result is ignored).
 * This is acceptable for keychain operations as they're fast and OS-bounded.
 * 
 * @param promise - The promise to wrap
 * @param timeoutMs - Timeout in milliseconds (should be validated via validateTimeout before calling)
 * @param operation - Name of the operation for error messages
 * @returns Promise that rejects on timeout
 * @throws {ValidationError} If timeoutMs is invalid
 * @throws {TimeoutError} If operation times out
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  // Note: validateTimeout should be called before this function to ensure timeoutMs is valid.
  // This function only performs basic safety checks for direct calls.
  if (typeof timeoutMs !== 'number' || !isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ValidationError(`Invalid timeout value: ${timeoutMs}. Must be a positive finite number.`)
  }
  
  if (timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
    throw new ValidationError(
      `Timeout ${timeoutMs}ms is out of range. Must be between ${MIN_TIMEOUT_MS}ms and ${MAX_TIMEOUT_MS}ms.`
    )
  }
  
  const timeoutPromise = new Promise<T>((_, reject) => {
    setTimeout(() => {
      reject(new TimeoutError(`Operation ${operation} timed out after ${timeoutMs}ms`))
    }, timeoutMs)
  })
  
  return Promise.race([promise, timeoutPromise])
}

