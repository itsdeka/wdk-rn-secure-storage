import { ValidationError } from './errors'

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
 * Allows: alphanumeric, dots, dashes, underscores, and optional email-like format
 * 
 * Examples of valid identifiers:
 * - "user123" (simple identifier)
 * - "my_wallet" (with underscore)
 * - "test-identifier" (with dash)
 * - "user@example.com" (email format)
 * 
 * The email part (after @) is optional - simple identifiers are fully supported.
 */
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9._-]+(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$/

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
      'Identifier contains invalid characters. Allowed: alphanumeric, dots, dashes, underscores, and email format'
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

