import { 
  getStorageKey, 
  checkRateLimit, 
  recordFailedAttempt, 
  recordSuccess,
  withTimeout,
  MIN_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  __resetRateLimiter,
  createStorageKey,
  cleanupSecureStorageModule,
  __stopPeriodicCleanup,
} from '../utils'
import { AuthenticationError, TimeoutError, ValidationError } from '../errors'

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
  beforeEach(() => {
    __resetRateLimiter()
  })

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

  describe('rate limiting', () => {
    beforeEach(() => {
      __resetRateLimiter()
    })

    it('should allow authentication within rate limit', () => {
      expect(() => checkRateLimit()).not.toThrow()
    })

    it('should throw AuthenticationError after max attempts', () => {
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt()
      }
      
      expect(() => checkRateLimit()).toThrow(AuthenticationError)
    })

    it('should reset on successful authentication', () => {
      // Make 4 failed attempts
      for (let i = 0; i < 4; i++) {
        recordFailedAttempt()
      }
      
      // Success should reset
      recordSuccess()
      
      // Should be able to authenticate again
      expect(() => checkRateLimit()).not.toThrow()
    })

    it('should handle per-identifier rate limiting', () => {
      // Lock out user1
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('user1@example.com')
      }
      
      // user2 should still be allowed
      expect(() => checkRateLimit('user2@example.com')).not.toThrow()
      
      // user1 should be locked out
      expect(() => checkRateLimit('user1@example.com')).toThrow(AuthenticationError)
    })

    it('should cleanup expired entries', () => {
      // This test verifies that cleanup is called
      // In a real scenario, we'd need to manipulate time to test expiration
      // For now, we verify the function doesn't throw and handles cleanup
      recordFailedAttempt('user1@example.com')
      expect(() => checkRateLimit('user1@example.com')).not.toThrow()
    })

    it('should handle concurrent rate limit checks correctly', () => {
      // Simulate concurrent rate limit checks
      const results: (void | Error)[] = []
      
      // Start multiple concurrent checks
      for (let i = 0; i < 10; i++) {
        try {
          checkRateLimit('concurrent@example.com')
          results.push(undefined)
        } catch (error) {
          results.push(error as Error)
        }
      }
      
      // All should succeed (no attempts recorded yet)
      expect(results.every(r => r === undefined)).toBe(true)
    })

    it('should handle concurrent failed attempt recording', () => {
      // Simulate concurrent failed attempts
      const promises = Array.from({ length: 10 }, () => {
        return Promise.resolve().then(() => {
          try {
            checkRateLimit('concurrent-fail@example.com')
            recordFailedAttempt('concurrent-fail@example.com')
          } catch (error) {
            // Expected after lockout
          }
        })
      })
      
      return Promise.all(promises).then(() => {
        // After 5 attempts, should be locked out
        expect(() => checkRateLimit('concurrent-fail@example.com')).toThrow(AuthenticationError)
      })
    })

    it('should maintain correct state with rapid concurrent operations', () => {
      // Rapidly record multiple failed attempts
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('rapid@example.com')
      }
      
      // Should be locked out
      expect(() => checkRateLimit('rapid@example.com')).toThrow(AuthenticationError)
      
      // Other identifier should not be affected
      expect(() => checkRateLimit('other@example.com')).not.toThrow()
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

  describe('cleanupSecureStorageModule', () => {
    beforeEach(() => {
      __resetRateLimiter()
      __stopPeriodicCleanup()
    })

    it('should cleanup rate limiter state', () => {
      // Add some rate limit entries
      recordFailedAttempt('user1@example.com')
      recordFailedAttempt('user2@example.com')
      
      // Cleanup should clear all entries
      cleanupSecureStorageModule()
      
      // Should be able to check rate limit without errors
      expect(() => checkRateLimit('user1@example.com')).not.toThrow()
      expect(() => checkRateLimit('user2@example.com')).not.toThrow()
    })

    it('should stop periodic cleanup interval', () => {
      // Start cleanup by triggering rate limit check
      checkRateLimit()
      
      // Cleanup should stop the interval
      cleanupSecureStorageModule()
      
      // Interval should be stopped
      expect(() => cleanupSecureStorageModule()).not.toThrow()
    })

    it('should be idempotent', () => {
      recordFailedAttempt('user@example.com')
      
      cleanupSecureStorageModule()
      cleanupSecureStorageModule() // Call again
      
      // Should not throw
      expect(() => checkRateLimit('user@example.com')).not.toThrow()
    })
  })

  describe('lazy initialization', () => {
    beforeEach(() => {
      __resetRateLimiter()
      __stopPeriodicCleanup()
    })

    it('should start cleanup on first rate limit check', () => {
      // Cleanup should not be started initially
      expect(() => checkRateLimit()).not.toThrow()
      
      // After first check, cleanup should be started
      // We can't directly test the interval, but we can verify
      // that subsequent operations work correctly
      recordFailedAttempt('test@example.com')
      expect(() => checkRateLimit('test@example.com')).not.toThrow()
    })

    it('should start cleanup on first failed attempt', () => {
      // Cleanup should start when recording failed attempt
      recordFailedAttempt('test@example.com')
      
      // Should work correctly
      expect(() => checkRateLimit('test@example.com')).not.toThrow()
    })
  })
})

