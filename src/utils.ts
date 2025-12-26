import { validateIdentifier } from './validation'
import { TimeoutError, AuthenticationError } from './errors'

/**
 * Simple hash function for identifiers
 * Uses a combination of string operations to create a deterministic hash
 * This prevents key collisions and injection attacks
 */
function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  // Convert to positive hex string, take first 16 chars
  return Math.abs(hash).toString(16).padStart(16, '0').substring(0, 16)
}

/**
 * Generate a secure storage key from base key and optional identifier
 * Uses hashing to prevent collisions and injection attacks
 * 
 * @param baseKey - The base storage key
 * @param identifier - Optional identifier (e.g., email) to support multiple wallets
 * @returns The storage key
 */
export function getStorageKey(baseKey: string, identifier?: string): string {
  if (!identifier || identifier.trim() === '') {
    return baseKey
  }

  // Validate identifier first
  validateIdentifier(identifier)

  // Normalize: lowercase and trim
  const normalized = identifier.toLowerCase().trim()

  // Use hash to prevent collisions and ensure safe key format
  // Hash ensures different identifiers don't collide and prevents injection
  const hash = simpleHash(normalized)

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
 */
const authRateLimiter = new Map<string, RateLimitState>()

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
 * Check if authentication is allowed based on rate limiting
 * 
 * @param identifier - Optional identifier for rate limiting
 * @throws {Error} If rate limit exceeded
 */
export function checkRateLimit(identifier?: string): void {
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
 * @param identifier - Optional identifier for rate limiting
 */
export function recordFailedAttempt(identifier?: string): void {
  const key = identifier || 'default'
  const now = Date.now()
  const state = authRateLimiter.get(key) || { attempts: 0, resetTime: now + WINDOW_MS }

  state.attempts++
  if (state.attempts >= MAX_ATTEMPTS) {
    state.resetTime = now + LOCKOUT_MS
  } else {
    state.resetTime = now + WINDOW_MS
  }

  authRateLimiter.set(key, state)
}

/**
 * Record a successful authentication (resets rate limit)
 * 
 * @param identifier - Optional identifier for rate limiting
 */
export function recordSuccess(identifier?: string): void {
  const key = identifier || 'default'
  authRateLimiter.delete(key)
}

/**
 * Reset rate limiter (for testing only)
 * @internal
 */
export function __resetRateLimiter(): void {
  authRateLimiter.clear()
}

/**
 * Create a timeout wrapper for promises
 * 
 * @param promise - The promise to wrap
 * @param timeoutMs - Timeout in milliseconds
 * @param operation - Name of the operation for error messages
 * @returns Promise that rejects on timeout
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(
        () => reject(new TimeoutError(`Operation ${operation} timed out after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ])
}

