import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'
import {
  SecureStorageError,
  KeychainError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  ValidationError,
  TimeoutError,
} from './errors'
import { validateIdentifier, validateValue } from './validation'
import { Logger, defaultLogger, LogLevel } from './logger'
import {
  getStorageKey,
  checkRateLimit,
  recordFailedAttempt,
  recordSuccess,
  withTimeout,
} from './utils'

/**
 * Type-safe storage key names
 */
type StorageKey = string & { readonly __brand: 'StorageKey' }

/**
 * Secure storage keys (base keys without identifier)
 */
const STORAGE_KEYS = {
  ENCRYPTION_KEY: 'wallet_encryption_key' as StorageKey,
  ENCRYPTED_SEED: 'wallet_encrypted_seed' as StorageKey,
  ENCRYPTED_ENTROPY: 'wallet_encrypted_entropy' as StorageKey,
} as const

type StorageKeyName = keyof typeof STORAGE_KEYS

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
}

/**
 * Singleton instance of secure storage
 * Created lazily on first access
 */
let secureStorageInstance: SecureStorage | null = null

/**
 * Reset the singleton instance (for testing only)
 * @internal
 */
export function __resetSecureStorageInstance(): void {
  secureStorageInstance = null
}

/**
 * Default timeout for keychain operations (30 seconds)
 */
const DEFAULT_TIMEOUT_MS = 30000

/**
 * Secure storage wrapper factory for wallet credentials
 * 
 * Uses react-native-keychain which provides encrypted storage with cloud sync.
 * Returns a singleton instance to maintain referential equality across the app.
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
  // Return singleton instance if already created
  if (secureStorageInstance) {
    return secureStorageInstance
  }

  const logger = options?.logger || defaultLogger
  const authOptions = options?.authentication || {}
  const timeoutMs = options?.timeoutMs || DEFAULT_TIMEOUT_MS

  /**
   * Check if device authentication is available
   * This includes biometrics OR device PIN/password
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
   * @throws {ValidationError} If input validation fails
   * @throws {KeychainWriteError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
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
      const storageKey = getStorageKey(baseKey, identifier)

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
      if (error instanceof SecureStorageError) {
        logger.error(`Failed to store ${baseKey}`, error, { identifier })
        throw error
      }
      if (error instanceof TimeoutError) {
        logger.error(`Timeout storing ${baseKey}`, error, { identifier, timeoutMs })
        throw error
      }
      const keychainError = new KeychainWriteError(
        `Unexpected error storing ${baseKey}`,
        error as Error
      )
      logger.error(`Unexpected error storing ${baseKey}`, keychainError, { identifier })
      throw keychainError
    }
  }

  /**
   * Generic getter for secure values
   * 
   * @returns The stored value, or null if not found
   * @throws {ValidationError} If identifier validation fails
   * @throws {AuthenticationError} If authentication fails or rate limit exceeded
   * @throws {KeychainReadError} If keychain operation fails
   * @throws {TimeoutError} If operation times out
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

      const storageKey = getStorageKey(baseKey, identifier)

      logger.debug('Retrieving secure value', { baseKey, hasIdentifier: !!identifier })

      const keychainPromise = Keychain.getGenericPassword({
        service: storageKey,
      })

      const credentials = await withTimeout(
        keychainPromise,
        timeoutMs,
        `getSecureValue(${baseKey})`
      )

      if (credentials === false) {
        logger.debug('Secure value not found', { baseKey, hasIdentifier: !!identifier })
        return null
      }

      logger.info('Secure value retrieved successfully', { baseKey, hasIdentifier: !!identifier })
      return credentials.password
    } catch (error) {
      if (error instanceof AuthenticationError) {
        logger.error(`Authentication failed for ${baseKey}`, error, { identifier })
        throw error
      }
      if (error instanceof TimeoutError) {
        logger.error(`Timeout retrieving ${baseKey}`, error, { identifier, timeoutMs })
        throw error
      }
      if (error instanceof SecureStorageError) {
        logger.error(`Failed to get ${baseKey}`, error, { identifier })
        throw error
      }
      const readError = new KeychainReadError(
        `Unexpected error getting ${baseKey}`,
        error as Error
      )
      logger.error(`Unexpected error getting ${baseKey}`, readError, { identifier })
      throw readError
    }
  }

  // Create and cache the singleton instance
  secureStorageInstance = {
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
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns true if wallet exists, false otherwise
     * 
     * @throws {ValidationError} If identifier is invalid format
     * @throws {KeychainReadError} If keychain operation fails unexpectedly
     */
    async hasWallet(identifier?: string): Promise<boolean> {
      validateIdentifier(identifier)

      try {
        // Check if encrypted seed exists WITHOUT authentication
        // We're only checking existence, not reading sensitive data
        const seedStorageKey = getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
        const seedCredentials = await withTimeout(
          Keychain.getGenericPassword({
            service: seedStorageKey,
            // NO authenticationPrompt - we're just checking existence
          }),
          timeoutMs,
          'hasWallet'
        )

        if (seedCredentials === false) {
          return false
        }

        // Also check encryption key exists
        const encryptionKeyStorageKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
        const encryptionKeyCredentials = await withTimeout(
          Keychain.getGenericPassword({
            service: encryptionKeyStorageKey,
            // NO authenticationPrompt - we're just checking existence
          }),
          timeoutMs,
          'hasWallet'
        )

        return encryptionKeyCredentials !== false
      } catch (error) {
        // If it's an authentication error or not found, return false
        if (error instanceof AuthenticationError || error instanceof TimeoutError) {
          return false
        }
        // For other errors, log and rethrow
        logger.error('Failed to check if wallet exists', error as Error, { identifier })
        if (error instanceof SecureStorageError) {
          throw error
        }
        throw new KeychainReadError('Failed to check wallet existence', error as Error)
      }
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

      const encryptionKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
      const encryptedSeed = getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
      const encryptedEntropy = getStorageKey(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier)

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
        const failedServices = failures.map((f) => f.service.name).join(', ')
        const error = new SecureStorageError(
          `Failed to delete wallet: ${failedServices}`,
          'WALLET_DELETE_ERROR'
        )
        logger.error('Wallet deletion failed', error, {
          identifier,
          failedServices: failures.map((f) => f.service.name),
        })
        throw error
      }

      logger.info('Wallet deleted successfully', { identifier })
    },
  }

  return secureStorageInstance
}
