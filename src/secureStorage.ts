// External packages
import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

// Internal modules
import { DEFAULT_TIMEOUT_MS, DEVICE_AUTH_CACHE_TTL_MS } from './constants'
import {
  AuthenticationError,
  KeychainReadError,
  KeychainWriteError,
  SecureStorageError,
  TimeoutError,
  ValidationError,
} from './errors'
import { createKeychainOptions } from './keychainHelpers'
import { Logger, defaultLogger } from './logger'
import {
  createStorageKey,
  getStorageKey,
  isKeychainCredentials,
  type StorageKey,
  withTimeout,
} from './utils'
import {
  validateAuthenticationOptions,
  validateIdentifier,
  validateTimeout,
  validateValue,
} from './validation'

// Secure storage keys (base keys without identifier)
const ENCRYPTION_KEY = createStorageKey('wallet_encryption_key')
const ENCRYPTED_SEED = createStorageKey('wallet_encrypted_seed')
const ENCRYPTED_ENTROPY = createStorageKey('wallet_encrypted_entropy')

/**
 * Authentication options for biometric prompts
 */
export interface AuthenticationOptions {
  promptMessage?: string
  cancelLabel?: string
  disableDeviceFallback?: boolean
}

/**
 * Options for creating secure storage instance
 */
export interface SecureStorageOptions {
  logger?: Logger
  authentication?: AuthenticationOptions
  timeoutMs?: number
}

/**
 * Secure storage interface
 * 
 * All methods accept an optional identifier parameter to support multiple wallets.
 * When identifier is provided, it's used to create unique storage keys for each wallet.
 * When identifier is undefined or empty, default keys are used (backward compatibility).
 * 
 * Error Handling:
 * - Getters return null when data is not found
 * - All methods throw SecureStorageError or subclasses on failure
 * - Validation errors are thrown before any operations
 */
export interface SecureStorage {
  isBiometricAvailable(): Promise<boolean>
  authenticate(): Promise<boolean>
  setEncryptionKey(key: string, identifier?: string): Promise<void>
  getEncryptionKey(identifier?: string): Promise<string | null>
  setEncryptedSeed(encryptedSeed: string, identifier?: string): Promise<void>
  getEncryptedSeed(identifier?: string): Promise<string | null>
  setEncryptedEntropy(encryptedEntropy: string, identifier?: string): Promise<void>
  getEncryptedEntropy(identifier?: string): Promise<string | null>
  getAllEncrypted(identifier?: string): Promise<{
    encryptedSeed: string | null
    encryptedEntropy: string | null
    encryptionKey: string | null
  }>
  hasWallet(identifier?: string): Promise<boolean>
  deleteWallet(identifier?: string): Promise<void>
  /**
   * Cleanup method to release resources associated with this storage instance
   * 
   * This method should be called when the storage instance is no longer needed
   * to ensure proper cleanup of resources. Note that this does NOT delete stored
   * wallet data - use deleteWallet() for that purpose.
   * 
   * Currently, this is a no-op as the module uses shared resources, but it's
   * provided for future extensibility and to maintain a consistent API.
   */
  cleanup(): void
}

/**
 * Secure storage wrapper factory for wallet credentials
 * 
 * Uses react-native-keychain which provides encrypted storage with selective cloud sync.
 * Creates a new instance each time it's called, allowing different configurations
 * for different use cases. For most apps, you should create one instance and reuse it.
 * 
 * SECURITY:
 * - Storage is app-scoped by the OS (isolated by bundle ID/package name)
 * - iOS: Uses Keychain Services with iCloud Keychain sync (when user signed into iCloud)
 * - Android: Uses KeyStore with Google Cloud backup (when device backup enabled)
 * - Data is ALWAYS encrypted at rest by Keychain (iOS) / KeyStore (Android)
 * - Cloud sync behavior:
 *   - Encryption key: ACCESSIBLE.WHEN_UNLOCKED enables iCloud Keychain sync (iOS) and Google Cloud backup (Android)
 *   - Encrypted seed and entropy: ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY prevents cloud sync (device-only storage)
 * - Data is encrypted by Apple/Google's E2EE infrastructure
 * - Encryption key requires device unlock + biometric/PIN authentication to access (when available)
 * - Encrypted seed and entropy do not require authentication but are still encrypted at rest
 * - On devices without authentication, data is still encrypted at rest but accessible when device is unlocked
 * - Device-level keychain/keystore provides rate limiting and lockout mechanisms
 * - Input validation prevents injection attacks
 * 
 * Two different apps will NOT share data because storage is isolated by bundle ID/package name.
 * 
 * @param options - Optional configuration for logger, authentication messages, and timeouts
 * @returns SecureStorage instance
 * 
 * @example
 * ```typescript
 * const storage = createSecureStorage({
 *   logger: customLogger,
 *   authentication: {
 *     promptMessage: 'Authenticate to access wallet',
 *   },
 *   timeoutMs: 30000,
 * })
 * ```
 */
export function createSecureStorage(options?: SecureStorageOptions): SecureStorage {
  const logger = options?.logger || defaultLogger
  const authOptions = options?.authentication || {}
  
  // Validate timeout value if provided
  const requestedTimeout = validateTimeout(options?.timeoutMs)
  
  // Validate authentication options if provided
  validateAuthenticationOptions(authOptions)
  
  const timeoutMs = requestedTimeout || DEFAULT_TIMEOUT_MS

  // Cache for device authentication availability (per instance)
  // Cache expires after TTL to handle device settings changes
  let deviceAuthAvailableCache: { value: boolean; timestamp: number } | null = null

  /**
   * Error log message generators for consistent error handling
   */
  const getErrorLogMessage = (error: SecureStorageError, operation: string): string => {
    if (error instanceof AuthenticationError) {
      return `Authentication failed for ${operation}`
    }
    if (error instanceof TimeoutError) {
      return `Timeout during ${operation}`
    }
    if (error instanceof ValidationError) {
      return `Validation error during ${operation}`
    }
    return `Failed to ${operation}`
  }

  /**
   * Standardized error handling helper
   * 
   * @param error - The error to handle
   * @param operation - Name of the operation for logging
   * @param errorType - The error type to wrap unexpected errors in
   * @param context - Additional context for logging
   * @throws The error (either rethrown or wrapped)
   * @internal
   */
  function handleSecureStorageError<T extends SecureStorageError>(
    error: unknown,
    operation: string,
    errorType: new (message: string, cause?: Error) => T,
    context?: Record<string, unknown>
  ): never {
    if (error instanceof SecureStorageError) {
      const errorContext =
        error instanceof TimeoutError ? { ...context, timeoutMs } : context
      logger.error(getErrorLogMessage(error, operation), error, errorContext)
      throw error
    }

    const err = error instanceof Error ? error : new Error(String(error))
    const wrappedError = new errorType(`Unexpected error during ${operation}`, err)
    logger.error(`Unexpected error during ${operation}`, wrappedError, context)
    throw wrappedError
  }

  /**
   * Check if device authentication is available
   * This includes biometrics OR device PIN/password
   * 
   * Results are cached per instance with a 5-minute TTL to avoid repeated async calls
   * while allowing cache invalidation when device settings change.
   * 
   * @returns Promise that resolves to true if device authentication is available, false otherwise
   * @internal
   */
  async function isDeviceAuthenticationAvailable(): Promise<boolean> {
    const now = Date.now()
    
    // Return cached value if available and not expired
    if (deviceAuthAvailableCache !== null && (now - deviceAuthAvailableCache.timestamp) < DEVICE_AUTH_CACHE_TTL_MS) {
      return deviceAuthAvailableCache.value
    }

    try {
      const isEnrolled = await LocalAuthentication.isEnrolledAsync()
      deviceAuthAvailableCache = { value: isEnrolled, timestamp: now }
      return isEnrolled
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      logger.error('Failed to check device authentication availability', err, {})
      deviceAuthAvailableCache = { value: false, timestamp: now }
      return false
    }
  }


  /**
   * Check if biometric authentication is available
   */
  async function checkBiometricAvailable(): Promise<boolean> {
    try {
      const compatible = await LocalAuthentication.hasHardwareAsync()
      const enrolled = await LocalAuthentication.isEnrolledAsync()
      return compatible && enrolled
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error))
        logger.error('Failed to check biometric availability', err, {})
        return false
      }
  }

  /**
   * Authenticate with biometrics
   * 
   * @returns true if authentication succeeded, false otherwise
   */
  async function performAuthentication(): Promise<boolean> {
    try {
      const options = {
        promptMessage: authOptions.promptMessage || 'Authenticate to access your wallet',
        cancelLabel: authOptions.cancelLabel || 'Cancel',
        disableDeviceFallback: authOptions.disableDeviceFallback ?? false,
      }

      logger.debug('Starting biometric authentication')

      const result = await LocalAuthentication.authenticateAsync(options)

      if (result.success) {
        logger.info('Biometric authentication successful')
        return true
      } else {
        logger.warn('Biometric authentication failed or cancelled')
        return false
      }
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error))
        const authError = new AuthenticationError('Biometric authentication failed', err)
        logger.error('Biometric authentication error', authError, {})
        throw authError
      }
  }

  /**
   * Authenticate if device supports it
   * Returns true if authentication succeeded or was skipped (device doesn't support auth)
   * Returns false if authentication was required but failed
   */
  async function authenticateIfAvailable(identifier?: string): Promise<boolean> {
    // Check device auth first (cached) to avoid duplicate isEnrolledAsync calls
    const deviceAuthAvailable = await isDeviceAuthenticationAvailable()
    if (!deviceAuthAvailable) {
      return true // No auth available, skip
    }

    // Device auth is available, check if biometrics are available
    const biometricAvailable = await checkBiometricAvailable()
    if (!biometricAvailable) {
      // Device has PIN/password but no biometrics - proceed without prompt
      return true
    }

    // Biometrics available, attempt authentication
    const authenticated = await performAuthentication()
    if (authenticated) {
      logger.info('Authentication successful', { identifier })
    } else {
      logger.warn('Authentication failed', { identifier })
    }
    return authenticated
  }

  /**
   * Generic setter for secure values
   * 
   * @param baseKey - The base storage key (e.g., ENCRYPTION_KEY)
   * @param value - The value to store (must be non-empty string, max 10KB)
   * @param identifier - Optional identifier for multiple wallets
   * @param requireAuth - Whether authentication should be required (default: true)
   * @param syncable - Whether the value should sync across devices (default: true)
   * @throws {ValidationError} If input validation fails
   * @throws {KeychainWriteError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
   * @internal
   */
  async function setSecureValue(
    baseKey: StorageKey,
    value: string,
    identifier?: string,
    requireAuth: boolean = true,
    syncable: boolean = true
  ): Promise<void> {
    validateValue(value, 'value')
    validateIdentifier(identifier)

    try {
      const [deviceAuthAvailable, storageKey] = await Promise.all([
        isDeviceAuthenticationAvailable(),
        getStorageKey(baseKey, identifier),
      ])

      logger.debug('Storing secure value', { baseKey, identifier, requireAuth, syncable })

      const result = await withTimeout(
        Keychain.setGenericPassword(baseKey, value, {
          service: storageKey,
          ...createKeychainOptions(deviceAuthAvailable, requireAuth, syncable),
        }),
        timeoutMs,
        `setSecureValue(${baseKey})`
      )

      if (result === false) {
        throw new KeychainWriteError(`Failed to store ${baseKey}`)
      }

      logger.info('Secure value stored successfully', { baseKey, identifier })
    } catch (error) {
      handleSecureStorageError(
        error,
        `store ${baseKey}`,
        KeychainWriteError,
        { identifier, baseKey, requireAuth, syncable }
      )
    }
  }

  /**
   * Check if a key exists in keychain without reading its value
   * Used by hasWallet to check existence without authentication
   * 
   * @param storageKey - The storage key to check
   * @returns true if key exists with valid password, false if not found
   * @throws {KeychainReadError} If keychain operation fails (not just "key not found")
   * @throws {TimeoutError} If operation times out
   * @internal
   */
  async function checkKeyExists(storageKey: string): Promise<boolean> {
    try {
      const credentials = await withTimeout(
        Keychain.getGenericPassword({
          service: storageKey,
          // NO authenticationPrompt - we're just checking existence
        }),
        timeoutMs,
        `checkKeyExists(${storageKey})`
      )
      // Keychain.getGenericPassword returns:
      // - false when key doesn't exist (not an error, just missing)
      // - {username, password} object when key exists
      // - null in some edge cases (treat as not found)
      return isKeychainCredentials(credentials)
    } catch (error) {
      // Any exception here indicates a real keychain failure (not just "key not found")
      // These should be propagated as errors, not treated as "key doesn't exist"
      handleSecureStorageError(
        error,
        `check key existence (${storageKey})`,
        KeychainReadError,
        { storageKey }
      )
    }
  }

  /**
   * Generic getter for secure values
   * 
   * @param baseKey - The base storage key (e.g., ENCRYPTION_KEY)
   * @param identifier - Optional identifier for multiple wallets
   * @param requireAuth - Whether authentication is required (default: true)
   * @returns The stored value, or null if not found
   * @throws {ValidationError} If identifier validation fails
   * @throws {AuthenticationError} If authentication fails (when required)
   * @throws {KeychainReadError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
   * @internal
   */
  async function getSecureValue(
    baseKey: StorageKey,
    identifier: string | undefined,
    requireAuth: boolean = true
  ): Promise<string | null> {
    validateIdentifier(identifier)

    try {
      if (requireAuth && !(await authenticateIfAvailable(identifier))) {
        logger.warn('Authentication required but failed', { baseKey, identifier })
        throw new AuthenticationError('Authentication required but failed')
      }

      const storageKey = await getStorageKey(baseKey, identifier)
      logger.debug('Retrieving secure value', { baseKey, identifier })

      const credentials = await withTimeout(
        Keychain.getGenericPassword({ service: storageKey }),
        timeoutMs,
        `getSecureValue(${baseKey})`
      )

      if (!isKeychainCredentials(credentials)) {
        logger.debug('Secure value not found', { baseKey, identifier })
        return null
      }

      logger.info('Secure value retrieved successfully', { baseKey, identifier })
      return credentials.password
    } catch (error) {
      handleSecureStorageError(
        error,
        `get ${baseKey}`,
        KeychainReadError,
        { identifier, baseKey, requireAuth }
      )
    }
  }

  // Create and return the instance
  return {
    /**
     * Check if biometric authentication is available
     */
    async isBiometricAvailable(): Promise<boolean> {
      return checkBiometricAvailable()
    },

    /**
     * Authenticate with biometrics
     * 
     * @returns true if authentication succeeded, false otherwise
     */
    async authenticate(): Promise<boolean> {
      return performAuthentication()
    },

    /**
     * Store encryption key securely
     * 
     * @param key - The encryption key to store (must be non-empty string, max 10KB)
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @throws {ValidationError} If key or identifier is invalid
     * @throws {KeychainWriteError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     */
    async setEncryptionKey(key: string, identifier?: string): Promise<void> {
      return setSecureValue(ENCRYPTION_KEY, key, identifier, true, true)
    },

    /**
     * Get encryption key from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns The encryption key, or null if not found
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {AuthenticationError} If authentication fails
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     */
    async getEncryptionKey(identifier?: string): Promise<string | null> {
      return getSecureValue(ENCRYPTION_KEY, identifier)
    },

    /**
     * Store encrypted seed securely
     * 
     * @param encryptedSeed - The encrypted seed to store (must be non-empty string, max 10KB)
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * @throws {ValidationError} If encryptedSeed is invalid
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainWriteError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     * 
     * Note: Encrypted seed does not require authentication for access and is stored device-only (not synced across devices)
     */
    async setEncryptedSeed(encryptedSeed: string, identifier?: string): Promise<void> {
      return setSecureValue(ENCRYPTED_SEED, encryptedSeed, identifier, false, false)
    },

    /**
     * Get encrypted seed from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns The encrypted seed, or null if not found
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     * 
     * Note: Encrypted seed does not require authentication for access and is stored device-only (not synced across devices)
     */
    async getEncryptedSeed(identifier?: string): Promise<string | null> {
      return getSecureValue(ENCRYPTED_SEED, identifier, false)
    },

    /**
     * Store encrypted entropy securely
     * 
     * @param encryptedEntropy - The encrypted entropy to store (must be non-empty string, max 10KB)
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * @throws {ValidationError} If encryptedEntropy is invalid
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainWriteError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     * 
     * Note: Encrypted entropy does not require authentication for access and is stored device-only (not synced across devices)
     */
    async setEncryptedEntropy(encryptedEntropy: string, identifier?: string): Promise<void> {
      return setSecureValue(ENCRYPTED_ENTROPY, encryptedEntropy, identifier, false, false)
    },

    /**
     * Get encrypted entropy from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns The encrypted entropy, or null if not found
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     * 
     * Note: Encrypted entropy does not require authentication for access and is stored device-only (not synced across devices)
     */
    async getEncryptedEntropy(identifier?: string): Promise<string | null> {
      return getSecureValue(ENCRYPTED_ENTROPY, identifier, false)
    },

    /**
     * Get all encrypted wallet data at once (seed, entropy, and encryption key)
     * Uses Promise.all, so fails fast if any operation fails.
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns Object containing seed, entropy, and encryptionKey (may be null if not found)
     * @throws {ValidationError} If identifier is invalid format
     * @throws {AuthenticationError} If authentication fails
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     */
    async getAllEncrypted(identifier?: string): Promise<{
      encryptedSeed: string | null
      encryptedEntropy: string | null
      encryptionKey: string | null
    }> {
      const [encryptedSeed, encryptedEntropy, encryptionKey] = await Promise.all([
        this.getEncryptedSeed(identifier),
        this.getEncryptedEntropy(identifier),
        this.getEncryptionKey(identifier),
      ])

      return {
        encryptedSeed,
        encryptedEntropy,
        encryptionKey,
      }
    },

    /**
     * Check if wallet credentials exist (without requiring authentication)
     * Returns false only when wallet is definitively not found. Errors are thrown.
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns true if wallet exists, false if definitively not found
     * @throws {ValidationError} If identifier is invalid format
     * @throws {TimeoutError} If operation times out
     * @throws {KeychainReadError} If keychain operation fails
     */
    async hasWallet(identifier?: string): Promise<boolean> {
      // Batch storage key generation for efficiency
      const [seedStorageKey, encryptionKeyStorageKey] = await Promise.all([
        getStorageKey(ENCRYPTED_SEED, identifier),
        getStorageKey(ENCRYPTION_KEY, identifier),
      ])

      // Short-circuit: if seed doesn't exist, no need to check encryption key
      if (!(await checkKeyExists(seedStorageKey))) {
        return false
      }

      return await checkKeyExists(encryptionKeyStorageKey)
    },

    /**
     * Delete all wallet credentials
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {SecureStorageError} If deletion fails (with details of which items failed)
     * @throws {TimeoutError} If operation times out
     */
    async deleteWallet(identifier?: string): Promise<void> {
      // Batch storage key generation
      const [encryptionKey, encryptedSeed, encryptedEntropy] = await Promise.all([
        getStorageKey(ENCRYPTION_KEY, identifier),
        getStorageKey(ENCRYPTED_SEED, identifier),
        getStorageKey(ENCRYPTED_ENTROPY, identifier),
      ])

      const serviceKeys = [encryptionKey, encryptedSeed, encryptedEntropy]
      const serviceNames = ['encryptionKey', 'encryptedSeed', 'encryptedEntropy']

      logger.debug('Deleting wallet', { identifier, services: serviceNames })

      const results = await Promise.allSettled(
        serviceKeys.map((key) =>
          withTimeout(
            Keychain.resetGenericPassword({ service: key }),
            timeoutMs,
            `deleteWallet(${key})`
          )
        )
      )

      const failedServices = serviceNames.filter((_, index) => {
        const result = results[index]
        return result.status === 'rejected' || (result.status === 'fulfilled' && result.value === false)
      })

      if (failedServices.length > 0) {
        const error = new SecureStorageError(
          `Failed to delete wallet: ${failedServices.join(', ')}`,
          'WALLET_DELETE_ERROR'
        )
        logger.error('Wallet deletion failed', error, { identifier, failedServices })
        throw error
      }

      logger.info('Wallet deleted successfully', { identifier })
    },

    /**
     * Cleanup method to release resources associated with this storage instance
     * 
     * Currently, this is a no-op as the module uses shared resources. This method is provided
     * for future extensibility and to maintain a consistent API.
     * 
     * Note: This does NOT delete stored wallet data - use deleteWallet() for that purpose.
     */
    cleanup(): void {
      // Currently a no-op, but provided for future extensibility
      // If instance-specific resources are added in the future, they should be
      // cleaned up here
      logger.debug('Storage instance cleanup called (no-op)', {})
    },
  }
}
