/**
 * @tetherto/wdk-rn-secure-storage
 *
 * Secure storage abstractions for React Native
 * Provides secure storage for sensitive data (encrypted seeds, keys)
 */

// Main types and factory
export type { SecureStorage, SecureStorageOptions, AuthenticationOptions } from './secureStorage'
export { createSecureStorage } from './secureStorage'

// Error classes
export {
  SecureStorageError,
  KeychainError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  ValidationError,
  TimeoutError,
} from './errors'

// Logger types
export type { Logger, LogEntry } from './logger'
export { LogLevel, defaultLogger } from './logger'

// Validation constants (for advanced usage)
export { MAX_IDENTIFIER_LENGTH, MAX_VALUE_LENGTH } from './validation'
