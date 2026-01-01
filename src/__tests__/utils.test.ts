import { 
  getStorageKey, 
  withTimeout,
  isKeychainCredentials,
  createStorageKey,
} from '../utils'
import { MIN_TIMEOUT_MS, MAX_TIMEOUT_MS } from '../constants'
import { TimeoutError, ValidationError } from '../errors'

// Mock expo-crypto
jest.mock('expo-crypto', () => ({
  CryptoDigestAlgorithm: {
    SHA256: 'SHA256',
  },
  digestStringAsync: jest.fn(async (_algorithm: string, data: string) => {
    // Simple deterministic hash for testing
    let hash = 0
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0')
    return (hex.repeat(8)).substring(0, 64)
  }),
}))

describe('utils', () => {

  describe('getStorageKey', () => {
    it('should return base key when identifier is undefined', async () => {
      const storageKey = createStorageKey('wallet_encryption_key')
      const key = await getStorageKey(storageKey, undefined)
      expect(key).toBe('wallet_encryption_key')
    })

    it('should return base key when identifier is null', async () => {
      const storageKey = createStorageKey('wallet_encryption_key')
      const key = await getStorageKey(storageKey, null as any)
      expect(key).toBe('wallet_encryption_key')
    })

    it('should generate hashed key for identifier', async () => {
      const storageKey = createStorageKey('wallet_encryption_key')
      const key = await getStorageKey(storageKey, 'user@example.com')
      expect(key).toContain('wallet_encryption_key')
      expect(key).not.toBe('wallet_encryption_key')
      expect(key.length).toBeGreaterThan('wallet_encryption_key'.length)
    })

    it('should normalize identifier (lowercase and trim)', async () => {
      const storageKey = createStorageKey('wallet_encryption_key')
      const key1 = await getStorageKey(storageKey, 'User@Example.com')
      const key2 = await getStorageKey(storageKey, '  user@example.com  ')
      expect(key1).toBe(key2)
    })

    it('should throw ValidationError for invalid storage key', async () => {
      await expect(
        getStorageKey('invalid_key' as any, 'user@example.com')
      ).rejects.toThrow(ValidationError)
    })
  })

  describe('withTimeout', () => {
    it('should resolve if promise completes before timeout', async () => {
      const promise = Promise.resolve('success')
      const result = await withTimeout(promise, 1000, 'test')
      expect(result).toBe('success')
    })

    it('should throw TimeoutError if promise exceeds timeout', async () => {
      const promise = new Promise((resolve) => {
        setTimeout(() => resolve('too late'), 2000)
      })
      
      await expect(withTimeout(promise, MIN_TIMEOUT_MS, 'test')).rejects.toThrow(TimeoutError)
    }, 5000)

    it('should throw ValidationError for negative timeout', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, -1000, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for zero timeout', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, 0, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout below minimum', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, MIN_TIMEOUT_MS - 1, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout above maximum', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, MAX_TIMEOUT_MS + 1, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for NaN timeout', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, NaN, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for Infinity timeout', () => {
      const promise = Promise.resolve('success')
      expect(() => withTimeout(promise, Infinity, 'test')).toThrow(ValidationError)
    })

    it('should accept valid timeout values', async () => {
      const promise = Promise.resolve('success')
      const result = await withTimeout(promise, MIN_TIMEOUT_MS, 'test')
      expect(result).toBe('success')
    })

    it('should accept maximum timeout value', async () => {
      const promise = Promise.resolve('success')
      const result = await withTimeout(promise, MAX_TIMEOUT_MS, 'test')
      expect(result).toBe('success')
    })
  })


  describe('isKeychainCredentials', () => {
    it('should return true for valid credentials', () => {
      const credentials = {
        username: 'test',
        password: 'password123',
        service: 'test-service',
        storage: 'AES_GCM',
      }
      expect(isKeychainCredentials(credentials)).toBe(true)
    })

    it('should return true for credentials without storage', () => {
      const credentials = {
        username: 'test',
        password: 'password123',
        service: 'test-service',
      }
      expect(isKeychainCredentials(credentials)).toBe(true)
    })

    it('should return false for false', () => {
      expect(isKeychainCredentials(false)).toBe(false)
    })

    it('should return false for null', () => {
      expect(isKeychainCredentials(null)).toBe(false)
    })

    it('should return false for undefined', () => {
      expect(isKeychainCredentials(undefined)).toBe(false)
    })

    it('should return false for non-object', () => {
      expect(isKeychainCredentials('string')).toBe(false)
      expect(isKeychainCredentials(123)).toBe(false)
      expect(isKeychainCredentials([])).toBe(false)
    })

    it('should return false for object without password', () => {
      expect(isKeychainCredentials({ username: 'test', service: 'test' })).toBe(false)
    })

    it('should return false for object with non-string password', () => {
      expect(isKeychainCredentials({ username: 'test', password: 123, service: 'test' })).toBe(false)
      expect(isKeychainCredentials({ username: 'test', password: null, service: 'test' })).toBe(false)
    })

    it('should return false for object with empty password', () => {
      expect(isKeychainCredentials({ username: 'test', password: '', service: 'test' })).toBe(false)
    })

    it('should return true for object with non-empty password string', () => {
      expect(isKeychainCredentials({ username: 'test', password: 'a', service: 'test' })).toBe(true)
      expect(isKeychainCredentials({ username: 'test', password: 'valid', service: 'test' })).toBe(true)
    })
  })

})

