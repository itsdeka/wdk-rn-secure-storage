import {
  SecureStorageError,
  KeychainError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  ValidationError,
  TimeoutError,
} from '../errors'

describe('errors', () => {
  describe('SecureStorageError', () => {
    it('should create error with message and code', () => {
      const error = new SecureStorageError('Test error', 'TEST_CODE')
      expect(error.message).toBe('Test error')
      expect(error.code).toBe('TEST_CODE')
      expect(error.name).toBe('SecureStorageError')
    })

    it('should include cause error', () => {
      const cause = new Error('Original error')
      const error = new SecureStorageError('Test error', 'TEST_CODE', cause)
      expect(error.cause).toBe(cause)
    })
  })

  describe('KeychainError', () => {
    it('should create keychain error', () => {
      const error = new KeychainError('Keychain failed')
      expect(error.message).toBe('Keychain failed')
      expect(error.code).toBe('KEYCHAIN_ERROR')
      expect(error.name).toBe('KeychainError')
    })
  })

  describe('KeychainWriteError', () => {
    it('should create write error', () => {
      const error = new KeychainWriteError('Write failed')
      expect(error.code).toBe('KEYCHAIN_WRITE_ERROR')
      expect(error.name).toBe('KeychainWriteError')
    })
  })

  describe('KeychainReadError', () => {
    it('should create read error', () => {
      const error = new KeychainReadError('Read failed')
      expect(error.code).toBe('KEYCHAIN_READ_ERROR')
      expect(error.name).toBe('KeychainReadError')
    })
  })

  describe('AuthenticationError', () => {
    it('should create authentication error', () => {
      const error = new AuthenticationError('Auth failed')
      expect(error.code).toBe('AUTHENTICATION_ERROR')
      expect(error.name).toBe('AuthenticationError')
    })
  })

  describe('ValidationError', () => {
    it('should create validation error', () => {
      const error = new ValidationError('Invalid input')
      expect(error.code).toBe('VALIDATION_ERROR')
      expect(error.name).toBe('ValidationError')
    })
  })

  describe('TimeoutError', () => {
    it('should create timeout error', () => {
      const error = new TimeoutError('Operation timed out')
      expect(error.code).toBe('TIMEOUT_ERROR')
      expect(error.name).toBe('TimeoutError')
    })
  })
})


