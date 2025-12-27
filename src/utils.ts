import { validateIdentifier } from './validation'
import { TimeoutError, AuthenticationError, ValidationError } from './errors'
import * as Crypto from 'expo-crypto'

/**
 * Production-ready hash function for identifiers using expo-crypto
 * 
 * Uses SHA-256 from expo-crypto, which is:
 * - Battle-tested: Used by millions of apps in production
 * - Well-maintained: Part of the Expo SDK with regular updates
 * - Cryptographically secure: SHA-256 is a standard cryptographic hash
 * - Excellent collision resistance: Virtually zero collision probability for practical use
 * - Fast: Native implementation optimized for performance
 * 
 * This replaces custom hash implementations with a proven, industry-standard solution.
 * 
 * @param str - Input string to hash
 * @returns Promise that resolves to a 64-character hexadecimal SHA-256 hash string
 */
async function hashIdentifier(str: string): Promise<string> {
  // Use SHA-256 from expo-crypto for production-grade hashing
  // This is a well-tested, battle-hardened implementation
  const hash = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    str
  )
  return hash
}

/**
 * Valid storage key names
 * These are the only allowed base keys for secure storage
 */
const VALID_STORAGE_KEYS = [
  'wallet_encryption_key',
  'wallet_encrypted_seed',
  'wallet_encrypted_entropy',
] as const

/**
 * Type-safe storage key names
 * Branded type to ensure only valid storage keys are used
 */
export type StorageKey = (typeof VALID_STORAGE_KEYS)[number] & { readonly __brand: 'StorageKey' }

/**
 * Runtime validation for storage keys
 * Ensures only valid base keys are used at runtime
 * 
 * @param key - The key to validate
 * @throws {ValidationError} If the key is not a valid storage key
 * @internal
 */
function assertValidStorageKey(key: string): asserts key is StorageKey {
  const validKey = VALID_STORAGE_KEYS.find((k) => k === key)
  if (!validKey) {
    throw new ValidationError(
      `Invalid storage key: ${key}. Valid keys are: ${VALID_STORAGE_KEYS.join(', ')}`
    )
  }
}

/**
 * Create a StorageKey from a string with runtime validation
 * Use this function to safely create StorageKey values
 * 
 * @param key - The key string to convert to StorageKey
 * @returns The validated StorageKey
 * @throws {ValidationError} If the key is not a valid storage key
 * @internal
 */
export function createStorageKey(key: string): StorageKey {
  assertValidStorageKey(key)
  return key as StorageKey
}

/**
 * Generate a secure storage key from base key and optional identifier
 * Uses SHA-256 hashing to prevent collisions and injection attacks
 * 
 * @param baseKey - The base storage key (must be a valid StorageKey)
 * @param identifier - Optional identifier (e.g., email) to support multiple wallets
 * @returns Promise that resolves to the storage key
 * @throws {ValidationError} If baseKey is not a valid storage key
 */
export async function getStorageKey(baseKey: StorageKey, identifier?: string): Promise<string> {
  // Validate baseKey at runtime to ensure type safety
  // Note: baseKey is already typed as StorageKey, but we validate at runtime
  // to catch any type system bypasses. The assertion is safe because StorageKey
  // is a branded string type, so baseKey is guaranteed to be a string.
  assertValidStorageKey(baseKey)
  
  // Handle undefined/null early
  if (identifier === undefined || identifier === null) {
    return baseKey
  }

  // Validate identifier first (this will throw for empty strings and invalid formats)
  validateIdentifier(identifier)

  // Normalize: lowercase and trim (validation ensures it's not empty after trim)
  const normalized = identifier.toLowerCase().trim()

  // Use SHA-256 hash from expo-crypto to prevent collisions and ensure safe key format
  // This is a battle-tested, production-ready solution
  const hash = await hashIdentifier(normalized)

  return `${baseKey}_${hash}`
}

/**
 * Rate limiting state for authentication attempts
 */
interface RateLimitState {
  attempts: number
  resetTime: number
}

/**
 * Rate limiter storage (in-memory, per identifier)
 * 
 * **IMPORTANT SECURITY CONSIDERATIONS:**
 * 
 * This rate limiting is NOT redundant with OS-level protections. It provides
 * defense-in-depth security:
 * 
 * **OS-level protections (iOS/Android):**
 * - Protect the keychain/keystore item itself
 * - Lock out biometrics after device-level failures
 * - Require device PIN/password after too many biometric failures
 * 
 * **App-level rate limiting (this implementation):**
 * - Prevents the app from repeatedly calling authentication prompts
 * - Stops prompt spam even if each prompt has OS protections
 * - Provides consistent, predictable behavior across platforms
 * - Adds defense-in-depth security layer
 * 
 * **SHARED STATE ACROSS INSTANCES:**
 * 
 * This rate limiter Map is shared across ALL storage instances created by
 * `createSecureStorage()`. This means:
 * - Rate limiting is global, not per-instance
 * - All storage instances share the same rate limit state
 * - This is intentional and provides consistent security behavior
 * 
 * **IN-MEMORY RATE LIMITING:**
 * 
 * Rate limiting state is stored in memory and resets on app restart. This means:
 * - An attacker could potentially bypass rate limiting by restarting the app
 * - However, this is generally acceptable for mobile apps because:
 *   - Restarting requires user interaction (not easily automated)
 *   - The app is typically running in the foreground during authentication
 *   - The device itself provides additional security layers (device lock, biometrics)
 *   - OS-level protections still apply regardless of app restart
 * 
 * **Security Implications:**
 * - In-memory rate limiting: Prevents rapid-fire attempts within a session,
 *   but resets on app restart. Provides defense-in-depth on top of OS-level
 *   protections (keychain/keystore rate limiting).
 * - Persistent rate limiting: Would survive app restarts but requires
 *   additional secure storage operations and proper state management.
 * 
 * For most use cases, the current in-memory implementation provides adequate
 * security when combined with OS-level protections. For high-security scenarios
 * requiring persistent rate limiting, implement a wrapper that stores rate
 * limit state in secure storage.
 */
const authRateLimiter = new Map<string, RateLimitState>()

/**
 * Interval ID for periodic cleanup (null if not started)
 * @internal
 */
let cleanupIntervalId: ReturnType<typeof setInterval> | null = null

/**
 * Interval for periodic cleanup (5 minutes)
 * This ensures expired entries are cleaned up even if no rate limit checks occur
 */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000

/**
 * Maximum authentication attempts before lockout
 */
const MAX_ATTEMPTS = 5

/**
 * Time window for rate limiting (15 minutes)
 */
const WINDOW_MS = 15 * 60 * 1000

/**
 * Lockout duration after max attempts (30 minutes)
 */
const LOCKOUT_MS = 30 * 60 * 1000

/**
 * Maximum number of rate limit entries to prevent unbounded memory growth
 * 
 * If this limit is exceeded during cleanup, the oldest entries (by reset time)
 * are removed first. This prevents memory leaks when many unique identifiers
 * are used rapidly.
 * 
 * The value of 1000 is chosen to balance memory usage with practical use cases.
 * In most applications, the number of unique identifiers (e.g., user emails)
 * will be much lower than this limit.
 */
const MAX_RATE_LIMITER_ENTRIES = 1000

/**
 * Clean up expired rate limit entries to prevent memory leaks
 * 
 * This function removes rate limit entries that have passed their reset time.
 * It is called automatically during rate limit checks and periodically via
 * a setInterval timer to ensure memory doesn't grow unbounded.
 * 
 * If the rate limiter exceeds MAX_RATE_LIMITER_ENTRIES, the oldest entries
 * (by reset time) are removed first to prevent memory leaks.
 * 
 * @internal
 */
function cleanupExpiredEntries(): void {
  const now = Date.now()
  const keysToDelete: string[] = []
  
  // First, remove expired entries
  for (const [key, state] of authRateLimiter.entries()) {
    if (now >= state.resetTime) {
      keysToDelete.push(key)
    }
  }
  
  for (const key of keysToDelete) {
    authRateLimiter.delete(key)
  }
  
  // If still over limit, remove oldest entries (by reset time)
  if (authRateLimiter.size > MAX_RATE_LIMITER_ENTRIES) {
    const entries = Array.from(authRateLimiter.entries())
    // Sort by reset time (oldest first)
    entries.sort((a, b) => a[1].resetTime - b[1].resetTime)
    
    // Remove oldest entries until under limit
    const toRemove = entries.slice(0, authRateLimiter.size - MAX_RATE_LIMITER_ENTRIES)
    for (const [key] of toRemove) {
      authRateLimiter.delete(key)
    }
  }
}

/**
 * Start periodic cleanup of expired rate limit entries
 * 
 * This function sets up a setInterval timer that periodically calls
 * cleanupExpiredEntries() to remove expired entries from the rate limiter Map.
 * This ensures memory doesn't grow unbounded even if no rate limit checks occur.
 * 
 * The cleanup interval is set to CLEANUP_INTERVAL_MS (5 minutes).
 * This function is idempotent - calling it multiple times has no effect.
 * 
 * The cleanup is started lazily on the first rate limit check to avoid
 * module-level side effects on import. This makes testing easier and
 * prevents issues in test environments where the module may be imported
 * multiple times.
 * 
 * @internal
 */
function startPeriodicCleanup(): void {
  // Only start if not already started
  if (cleanupIntervalId !== null) {
    return
  }
  
  cleanupIntervalId = setInterval(() => {
    cleanupExpiredEntries()
  }, CLEANUP_INTERVAL_MS)
}

/**
 * Stop periodic cleanup
 * 
 * This function stops the periodic cleanup interval and should be called
 * when the module is being unloaded or when cleanup is needed (e.g., in tests).
 * 
 * @internal
 */
export function __stopPeriodicCleanup(): void {
  if (cleanupIntervalId !== null) {
    clearInterval(cleanupIntervalId)
    cleanupIntervalId = null
  }
}

/**
 * Cleanup function for module unload
 * 
 * This function should be called when the module is being unloaded to prevent
 * memory leaks. It stops the periodic cleanup interval and clears all rate
 * limiting state.
 * 
 * Note: In React Native, this should be called manually when appropriate,
 * as there's no standard module unload hook. Consider calling this in your
 * app's cleanup lifecycle (e.g., when the app is backgrounded or unmounted).
 * 
 * @internal
 */
export function __cleanupModule(): void {
  __stopPeriodicCleanup()
  authRateLimiter.clear()
}

/**
 * Public API to cleanup module resources
 * 
 * This function stops the periodic cleanup interval and clears all rate
 * limiting state. It should be called when the module is no longer needed,
 * such as during app shutdown or hot-reload scenarios.
 * 
 * **Important Notes:**
 * - This does NOT delete stored wallet data - use `deleteWallet()` for that.
 * - This is typically only needed in specific scenarios (hot-reload, testing, app shutdown)
 * - For normal app usage, you generally don't need to call this manually
 * - The module automatically cleans up expired rate limit entries periodically
 * 
 * **When to call:**
 * - During hot-reload in development (to reset rate limiting state)
 * - In test teardown (to ensure clean state between tests)
 * - During app shutdown (optional, for explicit cleanup)
 * - When you want to reset rate limiting state programmatically
 * 
 * @example
 * ```typescript
 * import { cleanupSecureStorageModule } from '@tetherto/wdk-rn-secure-storage'
 * 
 * // Example 1: In React Native app lifecycle
 * import { AppState } from 'react-native'
 * 
 * AppState.addEventListener('change', (nextAppState) => {
 *   if (nextAppState === 'background') {
 *     // Optional: cleanup when app goes to background
 *     // Note: This is usually not necessary
 *   }
 * })
 * 
 * // Example 2: In test teardown
 * afterAll(() => {
 *   cleanupSecureStorageModule()
 * })
 * 
 * // Example 3: During hot-reload (development only)
 * if (__DEV__ && module.hot) {
 *   module.hot.dispose(() => {
 *     cleanupSecureStorageModule()
 *   })
 * }
 * ```
 */
export function cleanupSecureStorageModule(): void {
  __cleanupModule()
}

// Note: Periodic cleanup is started lazily on first rate limit check
// to avoid module-level side effects on import. This makes testing easier
// and prevents issues in test environments.

/**
 * Check if authentication is allowed based on rate limiting
 * Automatically cleans up expired entries to prevent memory leaks
 * 
 * This function lazily starts the periodic cleanup interval on first call
 * to avoid module-level side effects on import.
 * 
 * @param identifier - Optional identifier for rate limiting
 * @throws {AuthenticationError} If rate limit exceeded
 */
export function checkRateLimit(identifier?: string): void {
  // Lazy initialization: start periodic cleanup on first rate limit check
  // This avoids module-level side effects on import
  if (cleanupIntervalId === null) {
    startPeriodicCleanup()
  }
  
  // Clean up expired entries first to prevent memory leaks
  cleanupExpiredEntries()
  
  const key = identifier || 'default'
  const now = Date.now()
  const state = authRateLimiter.get(key)

  if (state) {
    if (now < state.resetTime) {
      if (state.attempts >= MAX_ATTEMPTS) {
        const minutesRemaining = Math.ceil((state.resetTime - now) / 1000 / 60)
        throw new AuthenticationError(
          `Too many authentication attempts. Please try again in ${minutesRemaining} minute${minutesRemaining !== 1 ? 's' : ''}.`
        )
      }
    } else {
      // Reset window expired, clear the state
      authRateLimiter.delete(key)
    }
  }
}

/**
 * Record a failed authentication attempt
 * 
 * **Thread Safety in React Native:**
 * 
 * This function is safe for concurrent use in React Native because:
 * 
 * 1. **Single-Threaded Execution**: React Native's JavaScript execution is
 *    single-threaded. All operations run on the same thread, so there are no
 *    true race conditions between concurrent async operations.
 * 
 * 2. **Atomic Map Operations**: JavaScript Map.get() and Map.set() operations
 *    are atomic at the engine level. Even with rapid concurrent calls, each
 *    operation completes fully before the next one starts.
 * 
 * 3. **Read-Modify-Write Safety**: We calculate the new state before writing,
 *    minimizing the window between read and write. In the worst case, concurrent
 *    operations might both read the same state and increment it, but this is
 *    acceptable - it means the rate limit might be slightly more lenient, not
 *    less secure.
 * 
 * 4. **No Data Corruption**: The worst-case scenario is that attempt counts
 *    might be slightly inaccurate under extreme concurrency, but the rate
 *    limiting will still function correctly and provide security.
 * 
 * **Note**: In a true multi-threaded environment (e.g., with Web Workers),
 * additional synchronization primitives would be needed. This is not applicable
 * to React Native's execution model.
 * 
 * @param identifier - Optional identifier for rate limiting
 */
export function recordFailedAttempt(identifier?: string): void {
  // Lazy initialization: start periodic cleanup on first rate limit operation
  if (cleanupIntervalId === null) {
    startPeriodicCleanup()
  }
  
  // Clean up expired entries first
  cleanupExpiredEntries()
  
  const key = identifier || 'default'
  const now = Date.now()
  
  // Get current state (atomic read)
  const currentState = authRateLimiter.get(key)
  
  // Calculate new state (all calculations done before write)
  const currentAttempts = currentState?.attempts ?? 0
  const newAttempts = currentAttempts + 1
  const newResetTime = newAttempts >= MAX_ATTEMPTS
    ? now + LOCKOUT_MS
    : now + WINDOW_MS
  
  // Atomic write (single operation)
  authRateLimiter.set(key, {
    attempts: newAttempts,
    resetTime: newResetTime,
  })
}

/**
 * Record a successful authentication (resets rate limit)
 * Removes the rate limit entry for the given identifier, allowing unlimited
 * authentication attempts until the next failure.
 * 
 * @param identifier - Optional identifier for rate limiting. If not provided,
 *                     uses 'default' as the key.
 */
export function recordSuccess(identifier?: string): void {
  const key = identifier || 'default'
  authRateLimiter.delete(key)
}

/**
 * Reset rate limiter (for testing only)
 * 
 * Clears all rate limiting state. This function is intended for use in tests
 * to ensure a clean state between test cases. It should not be used in
 * production code.
 * 
 * @internal
 */
export function __resetRateLimiter(): void {
  authRateLimiter.clear()
  // Restart periodic cleanup after reset
  __stopPeriodicCleanup()
  startPeriodicCleanup()
}

/**
 * Minimum timeout value (1 second)
 */
export const MIN_TIMEOUT_MS = 1000

/**
 * Maximum timeout value (5 minutes)
 */
export const MAX_TIMEOUT_MS = 5 * 60 * 1000

/**
 * Create a timeout wrapper for promises
 * 
 * **IMPORTANT SECURITY & RESOURCE CONSIDERATION:**
 * 
 * This function uses Promise.race() which does NOT cancel the underlying promise.
 * The original promise will continue executing even after timeout, though its result
 * will be ignored. This means:
 * 
 * 1. **Resource Usage**: Under extreme load, timed-out keychain operations may
 *    continue executing in the background, potentially accumulating pending operations.
 * 
 * 2. **Memory**: The underlying promise and its resources are not immediately freed
 *    on timeout, though they will be garbage collected when the promise resolves.
 * 
 * 3. **Acceptability**: This is generally acceptable for keychain operations because:
 *    - Keychain operations are typically fast (< 1 second)
 *    - They are bounded in duration by the OS
 *    - The timeout is a safety mechanism, not a normal occurrence
 *    - React Native's single-threaded nature limits concurrent operations
 * 
 * 4. **Monitoring**: In production, monitor timeout frequency. If timeouts occur
 *    frequently, investigate keychain performance or increase timeout values.
 * 
 * **Future Enhancement**: If the keychain library adds AbortController support,
 * this implementation should be updated to properly cancel operations on timeout.
 * 
 * @param promise - The promise to wrap
 * @param timeoutMs - Timeout in milliseconds (must be between MIN_TIMEOUT_MS and MAX_TIMEOUT_MS)
 * @param operation - Name of the operation for error messages
 * @returns Promise that rejects on timeout
 * @throws {ValidationError} If timeoutMs is invalid
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  // Validate timeout value
  if (typeof timeoutMs !== 'number' || isNaN(timeoutMs) || !isFinite(timeoutMs)) {
    throw new ValidationError(`Invalid timeout value: ${timeoutMs}. Must be a finite number.`)
  }
  
  if (timeoutMs < MIN_TIMEOUT_MS) {
    throw new ValidationError(`Timeout ${timeoutMs}ms is too short. Minimum is ${MIN_TIMEOUT_MS}ms.`)
  }
  
  if (timeoutMs > MAX_TIMEOUT_MS) {
    throw new ValidationError(`Timeout ${timeoutMs}ms is too long. Maximum is ${MAX_TIMEOUT_MS}ms.`)
  }
  
  // Track timeout for monitoring (the promise will continue executing even after timeout)
  const timeoutPromise = new Promise<T>((_, reject) => {
    setTimeout(() => {
      // Log timeout occurrence for monitoring
      // Note: In production, this should be sent to your monitoring service
      // The underlying promise continues executing but its result is ignored
      const timeoutError = new TimeoutError(`Operation ${operation} timed out after ${timeoutMs}ms`)
      reject(timeoutError)
    }, timeoutMs)
  })
  
  return Promise.race([promise, timeoutPromise])
}

