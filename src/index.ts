/**
 * @tetherto/wdk-rn-secure-storage
 *
 * Secure storage abstractions for React Native
 * Provides secure storage for sensitive data (encrypted seeds, keys)
 * 
 * **Note on Internal Types:** Some internal types like `StorageKey` are intentionally
 * not exported. These are implementation details that consumers should not use directly.
 * Use the public API methods (setEncryptionKey, getEncryptionKey, etc.) instead.
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

// Cleanup API (for advanced usage)
export { cleanupSecureStorageModule } from './utils'
