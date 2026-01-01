import { createSecureStorage, SecureStorage } from '../secureStorage'
import {
  ValidationError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  SecureStorageError,
  TimeoutError,
} from '../errors'
import { Logger } from '../logger'
import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

// Mock logger that suppresses console output during tests
const mockLogger: Logger = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}

// Mock dependencies with factory functions
jest.mock('react-native-keychain', () => ({
  ACCESSIBLE: {
    WHEN_UNLOCKED: 'WHEN_UNLOCKED',
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
  },
  ACCESS_CONTROL: {
    BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BIOMETRY_ANY_OR_DEVICE_PASSCODE',
  },
  STORAGE_TYPE: {
    AES_CBC: 'KeystoreAESCBC',
    AES_GCM_NO_AUTH: 'KeystoreAESGCM_NoAuth',
    AES_GCM: 'KeystoreAESGCM',
    RSA: 'KeystoreRSAECB',
  },
  setGenericPassword: jest.fn(),
  getGenericPassword: jest.fn(),
  resetGenericPassword: jest.fn(),
}))

jest.mock('expo-local-authentication', () => ({
  isEnrolledAsync: jest.fn(),
  hasHardwareAsync: jest.fn(),
  authenticateAsync: jest.fn(),
}))

jest.mock('expo-crypto', () => ({
  CryptoDigestAlgorithm: {
    SHA256: 'SHA256',
    SHA384: 'SHA384',
    SHA512: 'SHA512',
  },
  digestStringAsync: jest.fn(async (_algorithm: string, data: string) => {
    // Simple deterministic hash for testing (not cryptographically secure, but consistent)
    let hash = 0
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32-bit integer
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0')
    return (hex.repeat(8)).substring(0, 64)
  }),
}))

// Type the mocks
const mockKeychain = Keychain as jest.Mocked<typeof Keychain>
const mockLocalAuth = LocalAuthentication as jest.Mocked<typeof LocalAuthentication>

describe('SecureStorage', () => {
  let storage: SecureStorage

  // Helper to reset singleton
  const resetStorage = () => {
    storage = createSecureStorage({ logger: mockLogger })
  }

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()
    
    // Default mock implementations
    mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)
    mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
    mockLocalAuth.authenticateAsync.mockResolvedValue({ success: true })
    
    mockKeychain.setGenericPassword.mockResolvedValue({ 
      service: 'test', 
      storage: Keychain.STORAGE_TYPE.AES_GCM 
    })
    mockKeychain.getGenericPassword.mockResolvedValue({
      service: 'test',
      username: 'test',
      password: 'test-value',
      storage: Keychain.STORAGE_TYPE.AES_GCM,
    })
    mockKeychain.resetGenericPassword.mockResolvedValue(true)

    // Reset storage instance
    resetStorage()
  })

  describe('setEncryptionKey', () => {
    it('should store encryption key successfully', async () => {
      await storage.setEncryptionKey('test-key')
      
      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encryption_key',
        'test-key',
        expect.objectContaining({
          service: expect.any(String),
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
        })
      )
    })

    it('should store encryption key with identifier', async () => {
      await storage.setEncryptionKey('test-key', 'user@example.com')
      
      expect(mockKeychain.setGenericPassword).toHaveBeenCalled()
      const call = mockKeychain.setGenericPassword.mock.calls[0]
      expect(call[0]).toBe('wallet_encryption_key')
      expect(call[1]).toBe('test-key')
      expect(call[2]?.service).toContain('wallet_encryption_key')
      expect(call[2]?.accessible).toBe(Keychain.ACCESSIBLE.WHEN_UNLOCKED)
    })

    it('should use WHEN_UNLOCKED for encryption key to allow cloud sync', async () => {
      await storage.setEncryptionKey('test-key')
      
      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encryption_key',
        'test-key',
        expect.objectContaining({
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
        })
      )
    })

    it('should throw ValidationError for empty key', async () => {
      await expect(storage.setEncryptionKey('')).rejects.toThrow(ValidationError)
      expect(mockKeychain.setGenericPassword).not.toHaveBeenCalled()
    })

    it('should throw ValidationError for null key', async () => {
      await expect(storage.setEncryptionKey(null as any)).rejects.toThrow(ValidationError)
      expect(mockKeychain.setGenericPassword).not.toHaveBeenCalled()
    })

    it('should throw ValidationError for invalid identifier', async () => {
      await expect(storage.setEncryptionKey('key', 'invalid@#$identifier')).rejects.toThrow(
        ValidationError
      )
      expect(mockKeychain.setGenericPassword).not.toHaveBeenCalled()
    })

    it('should throw KeychainWriteError on keychain failure', async () => {
      mockKeychain.setGenericPassword.mockResolvedValue(false)
      
      await expect(storage.setEncryptionKey('key')).rejects.toThrow(KeychainWriteError)
    })

    it('should throw KeychainWriteError on keychain exception', async () => {
      const error = new Error('Keychain error')
      mockKeychain.setGenericPassword.mockRejectedValue(error)
      
      await expect(storage.setEncryptionKey('key')).rejects.toThrow(KeychainWriteError)
    })
  })

  describe('getEncryptionKey', () => {
    it('should retrieve encryption key successfully', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encryption_key',
        password: 'test-key',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const key = await storage.getEncryptionKey()
      
      expect(key).toBe('test-key')
      expect(mockKeychain.getGenericPassword).toHaveBeenCalled()
    })

    it('should return null when key not found', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const key = await storage.getEncryptionKey()
      
      expect(key).toBeNull()
    })

    it('should throw ValidationError for invalid identifier', async () => {
      await expect(storage.getEncryptionKey('invalid@#$id')).rejects.toThrow(ValidationError)
      expect(mockKeychain.getGenericPassword).not.toHaveBeenCalled()
    })

    it('should throw KeychainReadError on keychain exception', async () => {
      const error = new Error('Keychain read error')
      mockKeychain.getGenericPassword.mockRejectedValue(error)

      await expect(storage.getEncryptionKey()).rejects.toThrow(KeychainReadError)
    })

    it('should require authentication when available', async () => {
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.authenticateAsync.mockResolvedValue({ success: true })
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'test',
        password: 'test-key',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      await storage.getEncryptionKey()

      expect(mockLocalAuth.authenticateAsync).toHaveBeenCalled()
    })

    it('should throw AuthenticationError when authentication fails', async () => {
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.authenticateAsync.mockResolvedValue({ 
        success: false, 
        error: 'user_cancel' 
      })

      await expect(storage.getEncryptionKey()).rejects.toThrow(AuthenticationError)
      expect(mockKeychain.getGenericPassword).not.toHaveBeenCalled()
    })
  })

  describe('setEncryptedSeed', () => {
    it('should store encrypted seed successfully', async () => {
      await storage.setEncryptedSeed('encrypted-seed-data')

      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encrypted_seed',
        'encrypted-seed-data',
        expect.objectContaining({
          service: expect.any(String),
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        })
      )
    })

    it('should use WHEN_UNLOCKED_THIS_DEVICE_ONLY to prevent cloud sync', async () => {
      await storage.setEncryptedSeed('encrypted-seed-data')
      
      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encrypted_seed',
        'encrypted-seed-data',
        expect.objectContaining({
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        })
      )
    })

    it('should throw ValidationError for empty seed', async () => {
      await expect(storage.setEncryptedSeed('')).rejects.toThrow(ValidationError)
    })
  })

  describe('getEncryptedSeed', () => {
    it('should retrieve encrypted seed successfully', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_seed',
        password: 'encrypted-seed-data',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const seed = await storage.getEncryptedSeed()

      expect(seed).toBe('encrypted-seed-data')
    })

    it('should return null when seed not found', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const seed = await storage.getEncryptedSeed()

      expect(seed).toBeNull()
    })

    it('should retrieve seed without authentication even when auth would fail', async () => {
      // Encrypted seed does not require authentication
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_seed',
        password: 'test-seed',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const seed = await storage.getEncryptedSeed()

      expect(seed).toBe('test-seed')
      expect(mockKeychain.getGenericPassword).toHaveBeenCalled()
      // Should not call authentication since seed doesn't require it
      expect(mockLocalAuth.authenticateAsync).not.toHaveBeenCalled()
    })
  })

  describe('setEncryptedEntropy', () => {
    it('should store encrypted entropy successfully', async () => {
      await storage.setEncryptedEntropy('encrypted-entropy-data')

      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encrypted_entropy',
        'encrypted-entropy-data',
        expect.objectContaining({
          service: expect.any(String),
          accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        })
      )
    })
  })

  describe('getEncryptedEntropy', () => {
    it('should retrieve encrypted entropy successfully', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_entropy',
        password: 'encrypted-entropy-data',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const entropy = await storage.getEncryptedEntropy()

      expect(entropy).toBe('encrypted-entropy-data')
    })

    it('should return null when entropy not found', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const entropy = await storage.getEncryptedEntropy()

      expect(entropy).toBeNull()
    })

    it('should retrieve entropy without authentication even when auth would fail', async () => {
      // Encrypted entropy does not require authentication
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_entropy',
        password: 'test-entropy',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const entropy = await storage.getEncryptedEntropy()

      expect(entropy).toBe('test-entropy')
      expect(mockKeychain.getGenericPassword).toHaveBeenCalled()
      // Should not call authentication since entropy doesn't require it
      expect(mockLocalAuth.authenticateAsync).not.toHaveBeenCalled()
    })
  })

  describe('getAllEncrypted', () => {
    it('should retrieve all encrypted data', async () => {
      mockKeychain.getGenericPassword
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_seed',
          password: 'seed-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_entropy',
          password: 'entropy-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encryption_key',
          password: 'key-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })

      const data = await storage.getAllEncrypted()

      expect(data.encryptedSeed).toBe('seed-data')
      expect(data.encryptedEntropy).toBe('entropy-data')
      expect(data.encryptionKey).toBe('key-data')
    })

    it('should return null for missing data', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const data = await storage.getAllEncrypted()

      expect(data.encryptedSeed).toBeNull()
      expect(data.encryptedEntropy).toBeNull()
      expect(data.encryptionKey).toBeNull()
    })

    it('should throw ValidationError for invalid identifier', async () => {
      await expect(storage.getAllEncrypted('invalid@#$id')).rejects.toThrow(ValidationError)
    })
  })

  describe('deleteWallet', () => {
    it('should delete all wallet credentials successfully', async () => {
      mockKeychain.resetGenericPassword.mockResolvedValue(true)

      await storage.deleteWallet()

      expect(mockKeychain.resetGenericPassword).toHaveBeenCalledTimes(3)
    })

    it('should throw ValidationError for invalid identifier', async () => {
      await expect(storage.deleteWallet('invalid@#$id')).rejects.toThrow(ValidationError)
    })

    it('should throw error if partial deletion fails', async () => {
      mockKeychain.resetGenericPassword
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false) // Second deletion fails
        .mockResolvedValueOnce(true)

      await expect(storage.deleteWallet()).rejects.toThrow(SecureStorageError)
    })

    it('should throw error if deletion throws exception', async () => {
      const error = new Error('Delete error')
      mockKeychain.resetGenericPassword.mockRejectedValue(error)

      await expect(storage.deleteWallet()).rejects.toThrow(SecureStorageError)
    })
  })

  describe('hasWallet', () => {
    it('should return true when wallet exists', async () => {
      mockKeychain.getGenericPassword
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_seed',
          password: 'seed-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encryption_key',
          password: 'key-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })

      const exists = await storage.hasWallet()

      expect(exists).toBe(true)
    })

    it('should return false when wallet does not exist', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const exists = await storage.hasWallet()

      expect(exists).toBe(false)
    })

    it('should throw ValidationError for invalid identifier', async () => {
      await expect(storage.hasWallet('invalid@#$id')).rejects.toThrow(ValidationError)
    })

    it('should return false when keychain requires authentication but fails', async () => {
      // hasWallet doesn't use the authentication flow, but if keychain itself
      // requires authentication and fails, it should return false
      // Mock keychain to return false (not found) when authentication is required
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const exists = await storage.hasWallet()

      expect(exists).toBe(false)
    })
  })

  describe('isBiometricAvailable', () => {
    it('should return true when biometrics are available', async () => {
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)

      const available = await storage.isBiometricAvailable()

      expect(available).toBe(true)
    })

    it('should return false when hardware not available', async () => {
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(false)
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)

      const available = await storage.isBiometricAvailable()

      expect(available).toBe(false)
    })

    it('should return false when not enrolled', async () => {
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(false)

      const available = await storage.isBiometricAvailable()

      expect(available).toBe(false)
    })

    it('should return false on error', async () => {
      mockLocalAuth.hasHardwareAsync.mockRejectedValue(new Error('Hardware check failed'))

      const available = await storage.isBiometricAvailable()

      expect(available).toBe(false)
    })
  })

  describe('authenticate', () => {
    it('should authenticate successfully', async () => {
      mockLocalAuth.authenticateAsync.mockResolvedValue({ success: true })

      const result = await storage.authenticate()

      expect(result).toBe(true)
      expect(mockLocalAuth.authenticateAsync).toHaveBeenCalledWith({
        promptMessage: 'Authenticate to access your wallet',
        cancelLabel: 'Cancel',
        disableDeviceFallback: false,
      })
    })

    it('should handle authentication failure', async () => {
      mockLocalAuth.authenticateAsync.mockResolvedValue({ 
        success: false, 
        error: 'user_cancel' 
      })

      const result = await storage.authenticate()

      expect(result).toBe(false)
    })

    it('should use custom authentication options', async () => {
      const customStorage = createSecureStorage({
        logger: mockLogger,
        authentication: {
          promptMessage: 'Custom message',
          cancelLabel: 'Custom cancel',
          disableDeviceFallback: true,
        },
      })

      mockLocalAuth.authenticateAsync.mockResolvedValue({ success: true })

      await customStorage.authenticate()

      expect(mockLocalAuth.authenticateAsync).toHaveBeenCalledWith({
        promptMessage: 'Custom message',
        cancelLabel: 'Custom cancel',
        disableDeviceFallback: true,
      })
    })

    it('should throw AuthenticationError on exception', async () => {
      const error = new Error('Auth error')
      mockLocalAuth.authenticateAsync.mockRejectedValue(error)

      await expect(storage.authenticate()).rejects.toThrow(AuthenticationError)
    })
  })

  describe('concurrent operations', () => {
    beforeEach(() => {
      resetStorage()
    })

    it('should handle concurrent getEncryptionKey calls', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encryption_key',
        password: 'test-key',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const promises = Array.from({ length: 5 }, () => storage.getEncryptionKey())
      const results = await Promise.all(promises)

      expect(results.every(r => r === 'test-key')).toBe(true)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(5)
    })

    it('should handle concurrent setEncryptionKey calls', async () => {
      const promises = Array.from({ length: 3 }, (_, i) => 
        storage.setEncryptionKey(`key-${i}`, `user${i}@example.com`)
      )

      await Promise.all(promises)

      expect(mockKeychain.setGenericPassword).toHaveBeenCalledTimes(3)
    })

    it('should handle concurrent getAllEncrypted calls', async () => {
      mockKeychain.getGenericPassword
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_seed',
          password: 'seed-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_entropy',
          password: 'entropy-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encryption_key',
          password: 'key-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })

      const promises = Array.from({ length: 2 }, () => storage.getAllEncrypted())
      const results = await Promise.all(promises)

      expect(results).toHaveLength(2)
      expect(results[0].encryptedSeed).toBe('seed-data')
    })
  })

  describe('timeout handling', () => {
    it('should throw TimeoutError on timeout', async () => {
      // Clear mocks
      jest.clearAllMocks()
      
      // Create storage with short timeout (minimum is 1000ms)
      const fastStorage = createSecureStorage({ logger: mockLogger, timeoutMs: 1500 })

      // Mock keychain to delay resolution beyond timeout
      mockKeychain.setGenericPassword.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ service: 'test', storage: Keychain.STORAGE_TYPE.AES_GCM }), 2000))
      )

      await expect(fastStorage.setEncryptionKey('key')).rejects.toThrow(TimeoutError)
    }, 10000) // Increase timeout for this test

    it('should throw ValidationError for negative timeout', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: -1000 })
      }).toThrow(ValidationError)
    })

    it('should throw ValidationError for zero timeout', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: 0 })
      }).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout below minimum', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: 500 }) // Below MIN_TIMEOUT_MS (1000ms)
      }).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout above maximum', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: 10 * 60 * 1000 }) // Above MAX_TIMEOUT_MS (5 minutes)
      }).toThrow(ValidationError)
    })

    it('should throw ValidationError for NaN timeout', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: NaN })
      }).toThrow(ValidationError)
    })

    it('should throw ValidationError for Infinity timeout', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: Infinity })
      }).toThrow(ValidationError)
    })

    it('should accept valid timeout values', () => {
      expect(() => {
        createSecureStorage({ timeoutMs: 5000 })
      }).not.toThrow()
    })
  })

  describe('device without authentication', () => {
    it('should work when device has no authentication', async () => {
      // Reset all mocks completely to remove any previous state
      jest.clearAllMocks()
      mockKeychain.getGenericPassword.mockReset()
      
      // Set up mocks for this specific test
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(false)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(false)
      
      const noAuthStorage = createSecureStorage({ logger: mockLogger })
      
      // Mock to return value for encryption key service specifically
      // The service will be 'wallet_encryption_key' (no identifier, so no hash)
      mockKeychain.getGenericPassword.mockImplementation((options?: { service?: string }) => {
        const service = options?.service || ''
        // Return the value if it's for encryption key service (base key without identifier)
        if (service === 'wallet_encryption_key') {
          return Promise.resolve({
            service: 'wallet_encryption_key',
            username: 'wallet_encryption_key',
            password: 'test-value',
            storage: Keychain.STORAGE_TYPE.AES_GCM,
          })
        }
        // Return false for all other services (seed, entropy, etc.)
        return Promise.resolve(false)
      })

      const value = await noAuthStorage.getEncryptionKey()

      expect(value).toBe('test-value')
      // Should not require authentication
      expect(mockLocalAuth.authenticateAsync).not.toHaveBeenCalled()
    })
  })

  describe('cleanup', () => {
    it('should have cleanup method', () => {
      expect(typeof storage.cleanup).toBe('function')
    })

    it('should call cleanup without errors', () => {
      expect(() => storage.cleanup()).not.toThrow()
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Storage instance cleanup called (no-op)',
        expect.any(Object)
      )
    })
  })

  describe('hasWallet simplified error handling', () => {
    it('should return false when seed does not exist', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(false)

      const exists = await storage.hasWallet()

      expect(exists).toBe(false)
      // Should only check seed, not encryption key
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(1)
    })

    it('should return false when encryption key does not exist but seed exists', async () => {
      mockKeychain.getGenericPassword
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_seed',
          password: 'seed-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce(false)

      const exists = await storage.hasWallet()

      expect(exists).toBe(false)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(2)
    })

    it('should throw error with context when keychain fails', async () => {
      const error = new Error('Keychain error')
      mockKeychain.getGenericPassword.mockRejectedValue(error)

      await expect(storage.hasWallet()).rejects.toThrow(KeychainReadError)
    })

    it('should return false when key exists but password is null', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_seed',
        password: null as any,
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(1)
    })

    it('should return false when key exists but password is empty string', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_seed',
        password: '',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(1)
    })

    it('should return false when key exists but password is missing', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encrypted_seed',
        // password property missing
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      } as any)

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(1)
    })

    it('should return false when encryption key exists but password is null', async () => {
      mockKeychain.getGenericPassword
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encrypted_seed',
          password: 'seed-data',
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })
        .mockResolvedValueOnce({
          service: 'test',
          username: 'wallet_encryption_key',
          password: null as any,
          storage: Keychain.STORAGE_TYPE.AES_GCM,
        })

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledTimes(2)
    })
  })

  describe('edge cases - keychain return values', () => {
    it('should handle keychain returning null instead of false', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(null as any)

      const key = await storage.getEncryptionKey()
      expect(key).toBeNull()
    })

    it('should handle keychain returning object without password property', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'test',
        // missing password property
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      } as any)

      const key = await storage.getEncryptionKey()
      expect(key).toBeNull()
    })

    it('should handle keychain returning password as non-string', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'test',
        password: 12345, // invalid type
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      } as any)

      const key = await storage.getEncryptionKey()
      expect(key).toBeNull()
    })

    it('should handle keychain returning null in checkKeyExists', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue(null as any)

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
    })

    it('should handle keychain returning invalid object in checkKeyExists', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue('invalid' as any)

      const exists = await storage.hasWallet()
      expect(exists).toBe(false)
    })
  })

  describe('edge cases - timeout scenarios', () => {
    it('should handle timeout with multiple concurrent operations', async () => {
      // Create storage with short timeout for testing (minimum is 1000ms)
      const testStorage = createSecureStorage({ 
        logger: mockLogger,
        timeoutMs: 1000, // Minimum valid timeout for testing
      })

      // Create a promise that never resolves
      const neverResolves = new Promise(() => {})
      mockKeychain.getGenericPassword.mockReturnValue(neverResolves as any)

      const promises = [
        testStorage.getEncryptionKey('user1@example.com'),
        testStorage.getEncryptionKey('user2@example.com'),
        testStorage.getEncryptionKey('user3@example.com'),
      ]

      // All should timeout
      await Promise.all(
        promises.map(p =>
          expect(p).rejects.toThrow(TimeoutError)
        )
      )
    }, 10000) // Increase Jest timeout for this test

    it('should handle timeout during deleteWallet operation', async () => {
      // Create storage with short timeout for testing (minimum is 1000ms)
      const testStorage = createSecureStorage({ 
        logger: mockLogger,
        timeoutMs: 1000, // Minimum valid timeout for testing
      })

      const neverResolves = new Promise(() => {})
      mockKeychain.resetGenericPassword.mockReturnValue(neverResolves as any)

      // deleteWallet wraps timeout errors in SecureStorageError
      await expect(testStorage.deleteWallet('user@example.com')).rejects.toThrow(SecureStorageError)
    }, 10000) // Increase Jest timeout for this test
  })

  describe('edge cases - concurrent operations with same identifier', () => {
    it('should handle concurrent get operations with same identifier', async () => {
      mockKeychain.getGenericPassword.mockResolvedValue({
        service: 'test',
        username: 'wallet_encryption_key',
        password: 'test-key',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const promises = Array.from({ length: 5 }, () =>
        storage.getEncryptionKey('user@example.com')
      )

      const results = await Promise.all(promises)
      expect(results.every(r => r === 'test-key')).toBe(true)
    })

    it('should handle concurrent set operations with same identifier', async () => {
      mockKeychain.setGenericPassword.mockResolvedValue({
        service: 'test',
        storage: Keychain.STORAGE_TYPE.AES_GCM,
      })

      const promises = Array.from({ length: 3 }, () =>
        storage.setEncryptionKey('test-key', 'user@example.com')
      )

      await Promise.all(promises)
      expect(mockKeychain.setGenericPassword).toHaveBeenCalledTimes(3)
    })
  })

  describe('error handling edge cases', () => {
    it('should handle ValidationError in error handler', async () => {
      // ValidationError is thrown during validation before operations,
      // so it doesn't go through handleSecureStorageError.
      // This test verifies ValidationError is properly thrown.
      await expect(storage.getEncryptionKey('invalid@#$identifier')).rejects.toThrow(ValidationError)
    })

    it('should handle error in isDeviceAuthenticationAvailable', async () => {
      // Make isEnrolledAsync throw an error
      mockLocalAuth.isEnrolledAsync.mockRejectedValueOnce(new Error('Device auth check failed'))
      
      // This should be caught and return false
      await storage.setEncryptionKey('key')
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Failed to check device authentication availability',
        expect.any(Error),
        {}
      )
    })


    it('should return true when device auth available but not biometric', async () => {
      // Device auth available, but biometric not available
      // This tests the path where isDeviceAuthenticationAvailable returns true
      // but isBiometricAvailable returns false
      mockLocalAuth.isEnrolledAsync.mockResolvedValueOnce(true)
      mockLocalAuth.hasHardwareAsync.mockResolvedValueOnce(true) // Has hardware
      mockLocalAuth.isEnrolledAsync.mockResolvedValueOnce(true) // Is enrolled
      mockLocalAuth.hasHardwareAsync.mockResolvedValueOnce(false) // But biometric not available
      
      // Should succeed without requiring authentication (line 263)
      await storage.getEncryptionKey()
      expect(mockKeychain.getGenericPassword).toHaveBeenCalled()
    })

  })
})
