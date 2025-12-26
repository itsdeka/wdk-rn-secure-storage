import { createSecureStorage, SecureStorage, __resetSecureStorageInstance } from '../secureStorage'
import {
  ValidationError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  SecureStorageError,
  TimeoutError,
} from '../errors'
import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

// Mock dependencies with factory functions
jest.mock('react-native-keychain', () => ({
  ACCESSIBLE: {
    WHEN_UNLOCKED: 'WHEN_UNLOCKED',
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

// Type the mocks
const mockKeychain = Keychain as jest.Mocked<typeof Keychain>
const mockLocalAuth = LocalAuthentication as jest.Mocked<typeof LocalAuthentication>

describe('SecureStorage', () => {
  let storage: SecureStorage

  // Helper to reset singleton
  const resetStorage = () => {
    __resetSecureStorageInstance()
    storage = createSecureStorage()
  }

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()
    
    // Reset rate limiter
    const { __resetRateLimiter } = require('../utils')
    __resetRateLimiter()
    
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
        expect.any(Object)
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

    it('should throw AuthenticationError when authentication fails', async () => {
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.authenticateAsync.mockResolvedValue({ 
        success: false, 
        error: 'user_cancel' 
      })

      await expect(storage.getEncryptedSeed()).rejects.toThrow(AuthenticationError)
      expect(mockKeychain.getGenericPassword).not.toHaveBeenCalled()
    })
  })

  describe('setEncryptedEntropy', () => {
    it('should store encrypted entropy successfully', async () => {
      await storage.setEncryptedEntropy('encrypted-entropy-data')

      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'wallet_encrypted_entropy',
        'encrypted-entropy-data',
        expect.any(Object)
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

    it('should throw AuthenticationError when authentication fails', async () => {
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(true)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(true)
      mockLocalAuth.authenticateAsync.mockResolvedValue({ 
        success: false, 
        error: 'user_cancel' 
      })

      await expect(storage.getEncryptedEntropy()).rejects.toThrow(AuthenticationError)
      expect(mockKeychain.getGenericPassword).not.toHaveBeenCalled()
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
      // Reset storage to get fresh instance with custom options
      __resetSecureStorageInstance()
      const customStorage = createSecureStorage({
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

  describe('rate limiting', () => {
    beforeEach(() => {
      // Reset rate limiter
      const { __resetRateLimiter } = require('../utils')
      __resetRateLimiter()
      resetStorage()
    })

    it('should allow authentication within rate limit', async () => {
      // Make 4 attempts (under limit of 5)
      for (let i = 0; i < 4; i++) {
        mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ 
          success: false, 
          error: 'user_cancel' 
        })
        await storage.authenticate()
      }

      // 5th attempt should still work
      mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ success: true })
      const result = await storage.authenticate()
      expect(result).toBe(true)
    })

    it('should enforce rate limit after max attempts', async () => {
      // Make 5 failed attempts
      for (let i = 0; i < 5; i++) {
        mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ 
          success: false, 
          error: 'user_cancel' 
        })
        await storage.authenticate()
      }

      // 6th attempt should throw AuthenticationError
      await expect(storage.authenticate()).rejects.toThrow(AuthenticationError)
    })

    it('should reset rate limit on successful authentication', async () => {
      // Make 4 failed attempts
      for (let i = 0; i < 4; i++) {
        mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ 
          success: false, 
          error: 'user_cancel' 
        })
        await storage.authenticate()
      }

      // Successful attempt should reset
      mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ success: true })
      await storage.authenticate()

      // Should be able to make more attempts
      mockLocalAuth.authenticateAsync.mockResolvedValueOnce({ success: true })
      const result = await storage.authenticate()
      expect(result).toBe(true)
    })
  })

  describe('timeout handling', () => {
    it('should throw TimeoutError on timeout', async () => {
      // Clear mocks
      jest.clearAllMocks()
      
      // Create storage with very short timeout
      __resetSecureStorageInstance()
      const fastStorage = createSecureStorage({ timeoutMs: 1 })

      // Mock keychain to delay resolution beyond timeout
      mockKeychain.setGenericPassword.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ service: 'test', storage: Keychain.STORAGE_TYPE.AES_GCM }), 100))
      )

      await expect(fastStorage.setEncryptionKey('key')).rejects.toThrow(TimeoutError)
    }, 10000) // Increase timeout for this test
  })

  describe('device without authentication', () => {
    it('should work when device has no authentication', async () => {
      // Reset all mocks completely to remove any previous state
      jest.clearAllMocks()
      mockKeychain.getGenericPassword.mockReset()
      
      // Reset storage to get fresh instance with no auth
      __resetSecureStorageInstance()
      
      // Reset rate limiter
      const { __resetRateLimiter } = require('../utils')
      __resetRateLimiter()
      
      // Set up mocks for this specific test
      mockLocalAuth.isEnrolledAsync.mockResolvedValue(false)
      mockLocalAuth.hasHardwareAsync.mockResolvedValue(false)
      
      const noAuthStorage = createSecureStorage()
      
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
})
