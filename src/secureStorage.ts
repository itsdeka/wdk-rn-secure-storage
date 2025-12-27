import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'
import {
  SecureStorageError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  ValidationError,
  TimeoutError,
} from './errors'
import { validateIdentifier, validateValue } from './validation'
import { Logger, defaultLogger } from './logger'
import {
  getStorageKey,
  checkRateLimit,
  recordFailedAttempt,
  recordSuccess,
  withTimeout,
  MIN_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  type StorageKey,
} from './utils'

/**
 * Secure storage keys (base keys without identifier)
 */
const STORAGE_KEYS = {
  ENCRYPTION_KEY: 'wallet_encryption_key' as StorageKey,
  ENCRYPTED_SEED: 'wallet_encrypted_seed' as StorageKey,
  ENCRYPTED_ENTROPY: 'wallet_encrypted_entropy' as StorageKey,
} as const

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
 * Default timeout for keychain operations (30 seconds)
 */
const DEFAULT_TIMEOUT_MS = 30000

/**
 * Secure storage wrapper factory for wallet credentials
 * 
 * Uses react-native-keychain which provides encrypted storage with cloud sync.
 * Creates a new instance each time it's called, allowing different configurations
 * for different use cases. For most apps, you should create one instance and reuse it.
 * 
 * SECURITY:
 * - Storage is app-scoped by the OS (isolated by bundle ID/package name)
 * - iOS: Uses Keychain Services with iCloud Keychain sync (when user signed into iCloud)
 * - Android: Uses KeyStore with Google Cloud backup (when device backup enabled)
 * - Data is ALWAYS encrypted at rest by Keychain (iOS) / KeyStore (Android)
 * - Cloud sync: ACCESSIBLE.WHEN_UNLOCKED enables iCloud Keychain sync (iOS) and Google Cloud backup (Android)
 * - Data is encrypted by Apple/Google's E2EE infrastructure
 * - Encryption key requires device unlock + biometric/PIN authentication to access (when available)
 * - Encrypted seed and entropy do not require authentication but are still encrypted at rest
 * - On devices without authentication, data is still encrypted at rest but accessible when device is unlocked
 * - Rate limiting prevents brute force attacks
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
  const requestedTimeout = options?.timeoutMs
  if (requestedTimeout !== undefined) {
    if (typeof requestedTimeout !== 'number' || isNaN(requestedTimeout) || !isFinite(requestedTimeout)) {
      throw new ValidationError(`Invalid timeout value: ${requestedTimeout}. Must be a finite number.`)
    }
    if (requestedTimeout < MIN_TIMEOUT_MS) {
      throw new ValidationError(`Timeout ${requestedTimeout}ms is too short. Minimum is ${MIN_TIMEOUT_MS}ms.`)
    }
    if (requestedTimeout > MAX_TIMEOUT_MS) {
      throw new ValidationError(`Timeout ${requestedTimeout}ms is too long. Maximum is ${MAX_TIMEOUT_MS}ms.`)
    }
  }
  
  // Validate authentication options if provided
  if (authOptions) {
    if (authOptions.promptMessage !== undefined) {
      if (typeof authOptions.promptMessage !== 'string') {
        throw new ValidationError('Authentication promptMessage must be a string')
      }
      if (authOptions.promptMessage.trim().length === 0) {
        throw new ValidationError('Authentication promptMessage cannot be empty')
      }
    }
    if (authOptions.cancelLabel !== undefined) {
      if (typeof authOptions.cancelLabel !== 'string') {
        throw new ValidationError('Authentication cancelLabel must be a string')
      }
      if (authOptions.cancelLabel.trim().length === 0) {
        throw new ValidationError('Authentication cancelLabel cannot be empty')
      }
    }
    if (authOptions.disableDeviceFallback !== undefined) {
      if (typeof authOptions.disableDeviceFallback !== 'boolean') {
        throw new ValidationError('Authentication disableDeviceFallback must be a boolean')
      }
    }
  }
  
  const timeoutMs = requestedTimeout || DEFAULT_TIMEOUT_MS

  /**
   * Standardized error handling helper
   * Ensures consistent error handling pattern across all operations
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
    // Check most specific error types first
    if (error instanceof AuthenticationError) {
      logger.error(`Authentication failed for ${operation}`, error, context)
      throw error
    }
    if (error instanceof TimeoutError) {
      logger.error(`Timeout during ${operation}`, error, { ...context, timeoutMs })
      throw error
    }
    if (error instanceof ValidationError) {
      logger.error(`Validation error during ${operation}`, error, context)
      throw error
    }
    // Then check generic SecureStorageError
    if (error instanceof SecureStorageError) {
      logger.error(`Failed to ${operation}`, error, context)
      throw error
    }
    // Finally, wrap unexpected errors
    const wrappedError = new errorType(
      `Unexpected error during ${operation}`,
      error as Error
    )
    logger.error(`Unexpected error during ${operation}`, wrappedError, context)
    throw wrappedError
  }

  /**
   * Check if device authentication is available
   * This includes biometrics OR device PIN/password
   * 
   * @returns Promise that resolves to true if device authentication is available, false otherwise
   * @internal
   */
  async function isDeviceAuthenticationAvailable(): Promise<boolean> {
    try {
      const isEnrolled = await LocalAuthentication.isEnrolledAsync()
      return isEnrolled
    } catch (error) {
      logger.error('Failed to check device authentication availability', error as Error)
      return false
    }
  }

  /**
   * Create keychain options with conditional access control
   * 
   * @param deviceAuthAvailable - Whether device authentication (biometrics/PIN) is available
   * @param requireAuth - Whether authentication should be required for this operation
   * @returns Keychain options object with appropriate access control settings
   * @internal
   */
  function createKeychainOptions(deviceAuthAvailable: boolean, requireAuth: boolean = true): Parameters<typeof Keychain.setGenericPassword>[2] {
    return {
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
      ...(requireAuth && deviceAuthAvailable && {
        accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
      }),
    }
  }

  /**
   * Authenticate if device supports it
   * Returns true if authentication succeeded or was skipped (device doesn't support auth)
   * Returns false if authentication was required but failed
   * 
   * @throws {AuthenticationError} If rate limit exceeded
   */
  async function authenticateIfAvailable(
    storage: SecureStorage,
    identifier?: string
  ): Promise<boolean> {
    try {
      checkRateLimit(identifier)
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error
      }
      throw new AuthenticationError('Rate limit check failed', error as Error)
    }

    const deviceAuthAvailable = await isDeviceAuthenticationAvailable()
    if (!deviceAuthAvailable) {
      return true // Skip auth if not available
    }

    const biometricAvailable = await storage.isBiometricAvailable()
    if (biometricAvailable) {
      const authenticated = await storage.authenticate()
      if (authenticated) {
        recordSuccess(identifier)
        logger.info('Authentication successful', { identifier })
      } else {
        recordFailedAttempt(identifier)
        logger.warn('Authentication failed', { identifier })
      }
      return authenticated
    }

    return true // Device auth available but not biometric
  }

  /**
   * Generic setter for secure values
   * 
   * Stores a secure value in keychain storage with appropriate access control.
   * 
   * @param baseKey - The base storage key (e.g., ENCRYPTION_KEY)
   * @param value - The value to store (must be non-empty string, max 10KB)
   * @param identifier - Optional identifier for multiple wallets
   * @param requireAuth - Whether authentication should be required for access (default: true)
   * @throws {ValidationError} If input validation fails
   * @throws {KeychainWriteError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
   * @internal
   */
  async function setSecureValue(
    baseKey: StorageKey,
    value: string,
    identifier?: string,
    requireAuth: boolean = true
  ): Promise<void> {
    // Validate inputs
    validateValue(value, 'value')
    validateIdentifier(identifier)

    try {
      const deviceAuthAvailable = await isDeviceAuthenticationAvailable()
      const storageKey = await getStorageKey(baseKey, identifier)

      logger.debug('Storing secure value', { baseKey, hasIdentifier: !!identifier, requireAuth })

      const keychainPromise = Keychain.setGenericPassword(baseKey, value, {
        service: storageKey,
        ...createKeychainOptions(deviceAuthAvailable, requireAuth),
      })

      const result = await withTimeout(
        keychainPromise,
        timeoutMs,
        `setSecureValue(${baseKey})`
      )

      if (result === false) {
        throw new KeychainWriteError(`Failed to store ${baseKey}`)
      }

      logger.info('Secure value stored successfully', { baseKey, hasIdentifier: !!identifier })
    } catch (error) {
      handleSecureStorageError(
        error,
        `store ${baseKey}`,
        KeychainWriteError,
        { 
          identifier, 
          baseKey,
          hasIdentifier: identifier !== undefined && identifier !== null,
          requireAuth,
        }
      )
    }
  }

  /**
   * Check if a key exists in keychain without reading its value
   * Used by hasWallet to check existence without authentication
   * 
   * @param storageKey - The storage key to check
   * @returns true if key exists, false if not found
   * @throws {KeychainReadError} If keychain operation fails
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
      // Validate that credentials is not false and is a valid object
      return credentials !== false && credentials !== null && typeof credentials === 'object'
    } catch (error) {
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
   * Retrieves a secure value from keychain storage. If authentication is required,
   * it will prompt the user for biometric authentication before retrieving the value.
   * 
   * @param baseKey - The base storage key (e.g., ENCRYPTION_KEY)
   * @param identifier - Optional identifier for multiple wallets
   * @param storage - The SecureStorage instance (for authentication)
   * @param requireAuth - Whether authentication is required (default: true)
   * @returns The stored value, or null if not found
   * @throws {ValidationError} If identifier validation fails
   * @throws {AuthenticationError} If authentication fails or rate limit exceeded. Note: This is thrown when authentication is required but fails, not when the key is simply not found (which returns null).
   * @throws {KeychainReadError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
   * @internal
   */
  async function getSecureValue(
    baseKey: StorageKey,
    identifier: string | undefined,
    storage: SecureStorage,
    requireAuth: boolean = true
  ): Promise<string | null> {
    // Validate identifier
    validateIdentifier(identifier)

    try {
      if (requireAuth) {
        const authenticated = await authenticateIfAvailable(storage, identifier)
        if (!authenticated) {
          // Authentication failed - throw error instead of returning null
          // This allows calling code to distinguish between auth failure (don't delete wallet)
          // and key not found (different scenario)
          const authError = new AuthenticationError(
            'Authentication required but failed',
            undefined
          )
          logger.warn('Authentication required but failed', { baseKey, identifier })
          throw authError
        }
      }

      const storageKey = await getStorageKey(baseKey, identifier)

      logger.debug('Retrieving secure value', { baseKey, hasIdentifier: !!identifier })

      const keychainPromise = Keychain.getGenericPassword({
        service: storageKey,
      })

      const credentials = await withTimeout(
        keychainPromise,
        timeoutMs,
        `getSecureValue(${baseKey})`
      )

      if (credentials === false || !credentials || typeof credentials !== 'object' || !('password' in credentials)) {
        logger.debug('Secure value not found', { baseKey, hasIdentifier: !!identifier })
        return null
      }

      // Validate that password exists and is a string
      if (typeof credentials.password !== 'string') {
        logger.warn('Keychain returned invalid password type', { baseKey, hasIdentifier: !!identifier })
        return null
      }

      logger.info('Secure value retrieved successfully', { baseKey, hasIdentifier: !!identifier })
      return credentials.password
    } catch (error) {
      handleSecureStorageError(
        error,
        `get ${baseKey}`,
        KeychainReadError,
        { 
          identifier, 
          baseKey,
          hasIdentifier: identifier !== undefined && identifier !== null,
          requireAuth,
        }
      )
    }
  }

  // Create and return the instance
  return {
    /**
     * Check if biometric authentication is available
     */
    async isBiometricAvailable(): Promise<boolean> {
      try {
        const compatible = await LocalAuthentication.hasHardwareAsync()
        const enrolled = await LocalAuthentication.isEnrolledAsync()
        return compatible && enrolled
      } catch (error) {
        logger.error('Failed to check biometric availability', error as Error)
        return false
      }
    },

    /**
     * Authenticate with biometrics
     * 
     * @throws {AuthenticationError} If rate limit exceeded
     * @returns true if authentication succeeded, false otherwise
     */
    async authenticate(): Promise<boolean> {
      try {
        checkRateLimit()

        const options = {
          promptMessage: authOptions.promptMessage || 'Authenticate to access your wallet',
          cancelLabel: authOptions.cancelLabel || 'Cancel',
          disableDeviceFallback: authOptions.disableDeviceFallback ?? false,
        }

        logger.debug('Starting biometric authentication')

        const result = await LocalAuthentication.authenticateAsync(options)

        if (result.success) {
          recordSuccess()
          logger.info('Biometric authentication successful')
          return true
        } else {
          recordFailedAttempt()
          logger.warn('Biometric authentication failed or cancelled')
          return false
        }
      } catch (error) {
        recordFailedAttempt()
        if (error instanceof AuthenticationError) {
          throw error
        }
        const authError = new AuthenticationError('Biometric authentication failed', error as Error)
        logger.error('Biometric authentication error', authError)
        throw authError
      }
    },

    /**
     * Store encryption key securely
     * 
     * @param key - The encryption key to store (must be non-empty string, max 10KB)
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * @throws {ValidationError} If key is invalid (empty, too long, wrong type)
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainWriteError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     * 
     * @example
     * ```typescript
     * try {
     *   await storage.setEncryptionKey('my-key', 'user@example.com')
     * } catch (error) {
     *   if (error instanceof ValidationError) {
     *     // Handle validation error
     *   } else if (error instanceof KeychainWriteError) {
     *     // Handle keychain error
     *   }
     * }
     * ```
     */
    async setEncryptionKey(key: string, identifier?: string): Promise<void> {
      return setSecureValue(STORAGE_KEYS.ENCRYPTION_KEY, key, identifier)
    },

    /**
     * Get encryption key from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns The encryption key, or null if not found
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {AuthenticationError} If authentication fails or rate limit exceeded
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     */
    async getEncryptionKey(identifier?: string): Promise<string | null> {
      return getSecureValue(STORAGE_KEYS.ENCRYPTION_KEY, identifier, this)
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
     * Note: Encrypted seed does not require authentication for access
     */
    async setEncryptedSeed(encryptedSeed: string, identifier?: string): Promise<void> {
      return setSecureValue(STORAGE_KEYS.ENCRYPTED_SEED, encryptedSeed, identifier, false)
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
     * Note: Encrypted seed does not require authentication for access
     */
    async getEncryptedSeed(identifier?: string): Promise<string | null> {
      return getSecureValue(STORAGE_KEYS.ENCRYPTED_SEED, identifier, this, false)
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
     * Note: Encrypted entropy does not require authentication for access
     */
    async setEncryptedEntropy(encryptedEntropy: string, identifier?: string): Promise<void> {
      return setSecureValue(STORAGE_KEYS.ENCRYPTED_ENTROPY, encryptedEntropy, identifier, false)
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
     * Note: Encrypted entropy does not require authentication for access
     */
    async getEncryptedEntropy(identifier?: string): Promise<string | null> {
      return getSecureValue(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier, this, false)
    },

    /**
     * Get all encrypted wallet data at once (seed, entropy, and encryption key)
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns Object containing seed, entropy, and encryptionKey (may be null if not found)
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {AuthenticationError} If authentication fails or rate limit exceeded
     * @throws {KeychainReadError} If keychain operation fails
     * @throws {TimeoutError} If operation times out
     */
    async getAllEncrypted(identifier?: string): Promise<{
      encryptedSeed: string | null
      encryptedEntropy: string | null
      encryptionKey: string | null
    }> {
      validateIdentifier(identifier)

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
     * Check if wallet credentials exist
     * 
     * This method checks for wallet existence without requiring authentication.
     * It returns false only when the wallet is definitively not found.
     * Any errors (timeouts, keychain failures, etc.) are thrown rather than
     * returning false, allowing callers to distinguish between "not found"
     * and "error occurred".
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns true if wallet exists, false if definitively not found
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {TimeoutError} If operation times out
     * @throws {KeychainReadError} If keychain operation fails unexpectedly
     * 
     * @example
     * ```typescript
     * try {
     *   const exists = await storage.hasWallet('user@example.com')
     *   if (exists) {
     *     // Wallet exists
     *   } else {
     *     // Wallet does not exist
     *   }
     * } catch (error) {
     *   // Handle error (timeout, keychain failure, etc.)
     * }
     * ```
     */
    async hasWallet(identifier?: string): Promise<boolean> {
      validateIdentifier(identifier)

      // Check if encrypted seed exists WITHOUT authentication
      // We're only checking existence, not reading sensitive data
      const seedStorageKey = await getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
      const seedExists = await checkKeyExists(seedStorageKey)
      
      if (!seedExists) {
        return false
      }

      // Also check encryption key exists
      const encryptionKeyStorageKey = await getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
      const encryptionKeyExists = await checkKeyExists(encryptionKeyStorageKey)
      
      return encryptionKeyExists
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
      validateIdentifier(identifier)

      const encryptionKey = await getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
      const encryptedSeed = await getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
      const encryptedEntropy = await getStorageKey(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier)

      const services = [
        { name: 'encryptionKey', key: encryptionKey },
        { name: 'encryptedSeed', key: encryptedSeed },
        { name: 'encryptedEntropy', key: encryptedEntropy },
      ]

      logger.debug('Deleting wallet', { identifier, services: services.map(s => s.name) })

      const results = await Promise.allSettled(
        services.map(({ key }) =>
          withTimeout(
            Keychain.resetGenericPassword({ service: key }),
            timeoutMs,
            `deleteWallet(${key})`
          )
        )
      )

      const failures = results
        .map((result, index) => ({ result, service: services[index] }))
        .filter(
          ({ result }) =>
            result.status === 'rejected' || (result.status === 'fulfilled' && result.value === false)
        )

      if (failures.length > 0) {
        const failedServices = failures.map((f) => f.service ? f.service.name : 'unknown').join(', ')
        const error = new SecureStorageError(
          `Failed to delete wallet: ${failedServices}`,
          'WALLET_DELETE_ERROR'
        )
        logger.error('Wallet deletion failed', error, {
          identifier,
          failedServices: failures.map((f) => f.service ? f.service.name : 'unknown'),
        })
        throw error
      }

      logger.info('Wallet deleted successfully', { identifier })
    },

    /**
     * Cleanup method to release resources associated with this storage instance
     * 
     * Currently, this is a no-op as the module uses shared resources (rate limiter,
     * periodic cleanup) that are managed at the module level. This method is provided
     * for future extensibility and to maintain a consistent API.
     * 
     * Note: This does NOT delete stored wallet data - use deleteWallet() for that purpose.
     * Also, this does NOT stop the module-level periodic cleanup interval - that is
     * managed separately via __cleanupModule() in utils.ts.
     */
    cleanup(): void {
      // Currently a no-op, but provided for future extensibility
      // If instance-specific resources are added in the future, they should be
      // cleaned up here
      logger.debug('Storage instance cleanup called (no-op)', {})
    },
  }
}
