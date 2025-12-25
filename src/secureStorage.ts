import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

/**
 * Secure storage keys (base keys without identifier)
 */
const STORAGE_KEYS = {
  ENCRYPTION_KEY: 'wallet_encryption_key',
  ENCRYPTED_SEED: 'wallet_encrypted_seed',
  ENCRYPTED_ENTROPY: 'wallet_encrypted_entropy',
} as const

/**
 * Generate storage key with optional identifier
 * If identifier is provided, appends it to the base key
 * Otherwise returns the base key for backward compatibility
 */
function getStorageKey(baseKey: string, identifier?: string): string {
  if (!identifier || identifier.trim() === '') {
    return baseKey
  }
  // Normalize identifier: lowercase and trim
  const normalizedIdentifier = identifier.toLowerCase().trim()
  return `${baseKey}_${normalizedIdentifier}`
}

/**
 * Secure storage interface
 * 
 * All methods accept an optional identifier parameter to support multiple wallets.
 * When identifier is provided, it's used to create unique storage keys for each wallet.
 * When identifier is undefined or empty, default keys are used (backward compatibility).
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
 * Secure storage wrapper factory for wallet credentials
 * Uses react-native-keychain which provides encrypted storage with cloud sync
 * 
 * Returns a singleton instance to maintain referential equality across the app.
 * This eliminates the need for useMemo() in React components.
 * 
 * SECURITY NOTE: Storage is app-scoped by the OS:
 * - iOS: Uses Keychain Services with iCloud Keychain sync (when user signed into iCloud)
 * - Android: Uses KeyStore with Google Cloud backup (when device backup enabled)
 * 
 * CLOUD SYNC: Wallet credentials automatically sync to cloud for seamless device migration:
 * - iOS: ACCESSIBLE.WHEN_UNLOCKED enables iCloud Keychain synchronization
 * - Android: Default behavior backs up to Google Cloud when user has backup enabled
 * - Data is encrypted by Apple/Google's E2EE infrastructure
 * - Requires device unlock + biometric/PIN authentication to access
 * 
 * Two different apps will NOT share data because storage is isolated by bundle ID/package name.
 */
export function createSecureStorage(): SecureStorage {
  // Return singleton instance if already created
  if (secureStorageInstance) {
    return secureStorageInstance
  }
  /**
   * Internal helper: Check if device authentication is available
   * This includes biometrics OR device PIN/password
   * 
   * SECURITY NOTE: Even if device authentication is not available, SecureStore still
   * encrypts data at rest using OS-level encryption (Keychain on iOS, KeyStore on Android).
   * The requireAuthentication flag only controls whether accessing the data requires
   * authentication - it does NOT affect whether the data is encrypted.
   */
  async function isDeviceAuthenticationAvailable(): Promise<boolean> {
    try {
      // isEnrolledAsync() returns true if device has any authentication method:
      // - Biometrics (fingerprint, face, etc.)
      // - Device PIN/password/pattern
      const isEnrolled = await LocalAuthentication.isEnrolledAsync()
      
      // Note: On iOS, device passcode enables secure storage
      // On Android, device credentials (PIN/pattern/password) enable secure storage
      // hasHardwareAsync() checks for biometric hardware, but we don't require it
      // as long as device has some form of authentication enrolled
      return isEnrolled
    } catch (error) {
      console.error('Failed to check device authentication availability:', error)
      return false
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
        console.error('Failed to check biometric availability:', error)
        return false
      }
    },

    /**
     * Authenticate with biometrics
     */
    async authenticate(): Promise<boolean> {
      try {
        const result = await LocalAuthentication.authenticateAsync({
          promptMessage: 'Authenticate to access your wallet',
          cancelLabel: 'Cancel',
          disableDeviceFallback: false,
        })
        return result.success
      } catch (error) {
        console.error('Biometric authentication failed:', error)
        return false
      }
    },

    /**
     * Store encryption key securely
     * 
     * @param key - The encryption key to store
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * SECURITY: Data is ALWAYS encrypted at rest by Keychain (iOS) / KeyStore (Android).
     * With WHEN_UNLOCKED accessibility, the key will:
     * - Sync to iCloud Keychain (iOS) when user is signed into iCloud
     * - Backup to Google Cloud (Android) when device backup is enabled
     * - Be accessible only when device is unlocked
     * - Require biometric authentication if available
     * 
     * This allows seamless device migration while maintaining strong security.
     */
    async setEncryptionKey(key: string, identifier?: string): Promise<void> {
      const deviceAuthAvailable = await isDeviceAuthenticationAvailable()
      const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
      
      await Keychain.setGenericPassword(STORAGE_KEYS.ENCRYPTION_KEY, key, {
        service: storageKey,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED, // Enables iCloud Keychain sync
        // Only set accessControl if device authentication is available
        // Without accessControl, data is still encrypted at rest but doesn't require authentication
        ...(deviceAuthAvailable && {
          accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
        }),
      })
    },

    /**
     * Get encryption key from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * 
     * SECURITY: Data is encrypted at rest by Keychain (iOS) / KeyStore (Android).
     * Biometric authentication is enforced if available.
     * Data may be synced from iCloud Keychain (iOS) or Google Cloud (Android) on new devices.
     */
    async getEncryptionKey(identifier?: string): Promise<string | null> {
      try {
        console.log('🔐 Getting encryption key - checking authentication availability...')
        
        const deviceAuthAvailable = await isDeviceAuthenticationAvailable()
        console.log('🔐 Device authentication available:', deviceAuthAvailable)
        
        // Request authentication if available (biometrics or device credentials)
        if (deviceAuthAvailable) {
          const biometricAvailable = await this.isBiometricAvailable()
          if (biometricAvailable) {
            console.log('🔐 Requesting biometric authentication...')
            const authenticated = await this.authenticate()
            console.log('🔐 Biometric authentication result:', authenticated)
            
            if (!authenticated) {
              console.warn('⚠️  Biometric authentication cancelled or failed')
              return null
            }
          } else {
            console.log('🔐 Biometrics not available - will use device PIN/password')
          }
        } else {
          console.log('🔐 Device has no authentication - using encrypted storage without auth requirement')
        }

        // Retrieve key - will require authentication based on accessControl settings
        const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
        console.log('🔐 Retrieving encryption key from secure storage...', identifier ? `(identifier: ${identifier})` : '(default)')
        const credentials = await Keychain.getGenericPassword({
          service: storageKey,
        })
        
        if (!credentials) {
          console.log('🔐 No encryption key found')
          return null
        }
        
        console.log('✅ Encryption key retrieved successfully')
        return credentials.password
      } catch (error) {
        console.error('❌ Failed to get encryption key:', error)
        return null
      }
    },

    /**
     * Store encrypted seed securely
     * 
     * @param encryptedSeed - The encrypted seed to store
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async setEncryptedSeed(encryptedSeed: string, identifier?: string): Promise<void> {
      const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
      await Keychain.setGenericPassword(STORAGE_KEYS.ENCRYPTED_SEED, encryptedSeed, {
        service: storageKey,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED, // Enables iCloud Keychain sync
      })
    },

    /**
     * Get encrypted seed from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async getEncryptedSeed(identifier?: string): Promise<string | null> {
      try {
        const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
        const credentials = await Keychain.getGenericPassword({
          service: storageKey,
        })
        return credentials ? credentials.password : null
      } catch (error) {
        console.error('Failed to get encrypted seed:', error)
        return null
      }
    },

    /**
     * Store encrypted entropy securely
     * 
     * @param encryptedEntropy - The encrypted entropy to store
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async setEncryptedEntropy(encryptedEntropy: string, identifier?: string): Promise<void> {
      const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier)
      await Keychain.setGenericPassword(STORAGE_KEYS.ENCRYPTED_ENTROPY, encryptedEntropy, {
        service: storageKey,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED, // Enables iCloud Keychain sync
      })
    },

    /**
     * Get encrypted entropy from secure storage
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async getEncryptedEntropy(identifier?: string): Promise<string | null> {
      try {
        const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier)
        const credentials = await Keychain.getGenericPassword({
          service: storageKey,
        })
        return credentials ? credentials.password : null
      } catch (error) {
        console.error('Failed to get encrypted entropy:', error)
        return null
      }
    },

    /**
     * Get all encrypted wallet data at once (seed, entropy, and encryption key)
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     * @returns Object containing seed, entropy, and encryptionKey (may be null if not found)
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
     * Check if wallet credentials exist (without requiring biometric authentication)
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async hasWallet(identifier?: string): Promise<boolean> {
      try {
        const encryptedSeed = await this.getEncryptedSeed(identifier)
        if (!encryptedSeed) {
          return false
        }

        try {
          const storageKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
          const credentials = await Keychain.getGenericPassword({
            service: storageKey,
            authenticationPrompt: {
              title: 'Authenticate',
              cancel: 'Cancel',
            },
          })
          return credentials !== false
        } catch {
          return true
        }
      } catch (error) {
        console.error('Failed to check if wallet exists:', error)
        return false
      }
    },

    /**
     * Delete all wallet credentials
     * 
     * @param identifier - Optional identifier (e.g., email) to support multiple wallets
     */
    async deleteWallet(identifier?: string): Promise<void> {
      const encryptionKey = getStorageKey(STORAGE_KEYS.ENCRYPTION_KEY, identifier)
      const encryptedSeed = getStorageKey(STORAGE_KEYS.ENCRYPTED_SEED, identifier)
      const encryptedEntropy = getStorageKey(STORAGE_KEYS.ENCRYPTED_ENTROPY, identifier)
      
      await Promise.all([
        Keychain.resetGenericPassword({ service: encryptionKey }),
        Keychain.resetGenericPassword({ service: encryptedSeed }),
        Keychain.resetGenericPassword({ service: encryptedEntropy }),
      ])
    },
  }

  return secureStorageInstance
}

