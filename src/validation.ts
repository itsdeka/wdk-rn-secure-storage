import { ValidationError } from './errors'
import { MIN_TIMEOUT_MS, MAX_TIMEOUT_MS } from './constants'

/**
 * Authentication options for biometric prompts
 */
interface AuthenticationOptions {
  promptMessage?: string
  cancelLabel?: string
  disableDeviceFallback?: boolean
}

/**
 * Maximum length for identifier strings
 */
export const MAX_IDENTIFIER_LENGTH = 256

/**
 * Maximum length for stored values (10KB)
 */
export const MAX_VALUE_LENGTH = 10240

/**
 * Pattern for valid identifiers
 * Allows: alphanumeric, dots, dashes, underscores, plus signs, and optional email-like format
 * 
 * Examples of valid identifiers:
 * - "user123" (simple identifier)
 * - "my_wallet" (with underscore)
 * - "test-identifier" (with dash)
 * - "user@example.com" (email format)
 * - "user+tag@example.com" (email with plus sign in local part)
 * 
 * The email part (after @) is optional - simple identifiers are fully supported.
 */
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9._+-]+(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$/

/**
 * Validates an identifier parameter
 * 
 * @param identifier - The identifier to validate (optional)
 * @throws {ValidationError} If identifier is invalid
 */
export function validateIdentifier(identifier?: string): void {
  if (identifier === undefined || identifier === null) {
    return // Optional parameter is allowed
  }

  if (typeof identifier !== 'string') {
    throw new ValidationError('Identifier must be a string')
  }

  const trimmed = identifier.trim()
  if (trimmed === '') {
    throw new ValidationError('Identifier cannot be empty')
  }

  if (trimmed.length > MAX_IDENTIFIER_LENGTH) {
    throw new ValidationError(
      `Identifier exceeds maximum length of ${MAX_IDENTIFIER_LENGTH} characters`
    )
  }

  if (!IDENTIFIER_PATTERN.test(trimmed)) {
    throw new ValidationError(
      'Identifier contains invalid characters. Allowed: alphanumeric, dots, dashes, underscores, plus signs, and email format'
    )
  }
}

/**
 * Validates a value to be stored
 * 
 * @param value - The value to validate
 * @param fieldName - Name of the field for error messages
 * @throws {ValidationError} If value is invalid
 */
export function validateValue(value: string, fieldName: string = 'value'): void {
  if (value === null || value === undefined) {
    throw new ValidationError(`${fieldName} cannot be null or undefined`)
  }

  if (typeof value !== 'string') {
    throw new ValidationError(`${fieldName} must be a string`)
  }

  if (value.length === 0) {
    throw new ValidationError(`${fieldName} cannot be empty`)
  }

  if (value.length > MAX_VALUE_LENGTH) {
    throw new ValidationError(
      `${fieldName} exceeds maximum length of ${MAX_VALUE_LENGTH} characters`
    )
  }
}

/**
 * Validates a timeout value
 * 
 * @param timeoutMs - The timeout value to validate (optional)
 * @returns The validated timeout value, or undefined if not provided
 * @throws {ValidationError} If timeout is invalid
 */
export function validateTimeout(timeoutMs: number | undefined): number | undefined {
  if (timeoutMs === undefined) {
    return undefined
  }

  if (typeof timeoutMs !== 'number' || isNaN(timeoutMs) || !isFinite(timeoutMs)) {
    throw new ValidationError(`Invalid timeout value: ${timeoutMs}. Must be a finite number.`)
  }

  if (timeoutMs < MIN_TIMEOUT_MS) {
    throw new ValidationError(`Timeout ${timeoutMs}ms is too short. Minimum is ${MIN_TIMEOUT_MS}ms.`)
  }

  if (timeoutMs > MAX_TIMEOUT_MS) {
    throw new ValidationError(`Timeout ${timeoutMs}ms is too long. Maximum is ${MAX_TIMEOUT_MS}ms.`)
  }

  return timeoutMs
}

/**
 * Validates authentication options
 * 
 * @param options - The authentication options to validate (optional)
 * @throws {ValidationError} If any option is invalid
 */
export function validateAuthenticationOptions(options?: AuthenticationOptions): void {
  if (!options) {
    return
  }

  if (options.promptMessage !== undefined) {
    if (typeof options.promptMessage !== 'string') {
      throw new ValidationError('Authentication promptMessage must be a string')
    }
    if (options.promptMessage.trim().length === 0) {
      throw new ValidationError('Authentication promptMessage cannot be empty')
    }
  }

  if (options.cancelLabel !== undefined) {
    if (typeof options.cancelLabel !== 'string') {
      throw new ValidationError('Authentication cancelLabel must be a string')
    }
    if (options.cancelLabel.trim().length === 0) {
      throw new ValidationError('Authentication cancelLabel cannot be empty')
    }
  }

  if (options.disableDeviceFallback !== undefined) {
    if (typeof options.disableDeviceFallback !== 'boolean') {
      throw new ValidationError('Authentication disableDeviceFallback must be a boolean')
    }
  }
}

