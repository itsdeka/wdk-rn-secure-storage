import { validateIdentifier, validateValue, validateTimeout, validateAuthenticationOptions, MAX_IDENTIFIER_LENGTH, MAX_VALUE_LENGTH } from '../validation'
import { ValidationError } from '../errors'
import { MIN_TIMEOUT_MS, MAX_TIMEOUT_MS } from '../constants'

describe('validation', () => {
  describe('validateIdentifier', () => {
    it('should allow undefined identifier', () => {
      expect(() => validateIdentifier(undefined)).not.toThrow()
    })

    it('should allow null identifier', () => {
      expect(() => validateIdentifier(null as any)).not.toThrow()
    })

    it('should allow valid email identifier', () => {
      expect(() => validateIdentifier('user@example.com')).not.toThrow()
    })

    it('should allow email identifier with plus sign', () => {
      expect(() => validateIdentifier('dario.moceri+3@tether.to')).not.toThrow()
      expect(() => validateIdentifier('user+tag@example.com')).not.toThrow()
    })

    it('should allow valid alphanumeric identifier', () => {
      expect(() => validateIdentifier('user123')).not.toThrow()
      expect(() => validateIdentifier('user_123')).not.toThrow()
      expect(() => validateIdentifier('user-123')).not.toThrow()
      expect(() => validateIdentifier('user.123')).not.toThrow()
    })

    it('should throw ValidationError for non-string identifier', () => {
      expect(() => validateIdentifier(123 as any)).toThrow(ValidationError)
      expect(() => validateIdentifier({} as any)).toThrow(ValidationError)
      expect(() => validateIdentifier([] as any)).toThrow(ValidationError)
    })

    it('should throw ValidationError for empty string', () => {
      expect(() => validateIdentifier('')).toThrow(ValidationError)
      expect(() => validateIdentifier('   ')).toThrow(ValidationError)
    })

    it('should throw ValidationError for identifier exceeding max length', () => {
      const longIdentifier = 'a'.repeat(MAX_IDENTIFIER_LENGTH + 1)
      expect(() => validateIdentifier(longIdentifier)).toThrow(ValidationError)
    })

    it('should allow identifier at max length', () => {
      const maxIdentifier = 'a'.repeat(MAX_IDENTIFIER_LENGTH)
      expect(() => validateIdentifier(maxIdentifier)).not.toThrow()
    })

    it('should throw ValidationError for invalid characters', () => {
      expect(() => validateIdentifier('user@#$%example')).toThrow(ValidationError)
      expect(() => validateIdentifier('user example')).toThrow(ValidationError)
      expect(() => validateIdentifier('user\nexample')).toThrow(ValidationError)
    })
  })

  describe('validateValue', () => {
    it('should allow valid non-empty string', () => {
      expect(() => validateValue('valid value')).not.toThrow()
      expect(() => validateValue('a')).not.toThrow()
    })

    it('should throw ValidationError for null', () => {
      expect(() => validateValue(null as any, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for undefined', () => {
      expect(() => validateValue(undefined as any, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for non-string', () => {
      expect(() => validateValue(123 as any, 'test')).toThrow(ValidationError)
      expect(() => validateValue({} as any, 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for empty string', () => {
      expect(() => validateValue('', 'test')).toThrow(ValidationError)
    })

    it('should throw ValidationError for value exceeding max length', () => {
      const longValue = 'a'.repeat(MAX_VALUE_LENGTH + 1)
      expect(() => validateValue(longValue, 'test')).toThrow(ValidationError)
    })

    it('should allow value at max length', () => {
      const maxValue = 'a'.repeat(MAX_VALUE_LENGTH)
      expect(() => validateValue(maxValue, 'test')).not.toThrow()
    })

    it('should use custom field name in error message', () => {
      try {
        validateValue('', 'customField')
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError)
        expect((error as ValidationError).message).toContain('customField')
      }
    })
  })

  describe('validateTimeout', () => {
    it('should allow undefined timeout', () => {
      expect(() => validateTimeout(undefined)).not.toThrow()
      expect(validateTimeout(undefined)).toBeUndefined()
    })

    it('should allow valid timeout within range', () => {
      expect(() => validateTimeout(MIN_TIMEOUT_MS)).not.toThrow()
      expect(() => validateTimeout(MAX_TIMEOUT_MS)).not.toThrow()
      expect(() => validateTimeout(30000)).not.toThrow()
      expect(validateTimeout(30000)).toBe(30000)
    })

    it('should throw ValidationError for non-number', () => {
      expect(() => validateTimeout('1000' as any)).toThrow(ValidationError)
      expect(() => validateTimeout(null as any)).toThrow(ValidationError)
      expect(() => validateTimeout({} as any)).toThrow(ValidationError)
    })

    it('should throw ValidationError for NaN', () => {
      expect(() => validateTimeout(NaN)).toThrow(ValidationError)
    })

    it('should throw ValidationError for Infinity', () => {
      expect(() => validateTimeout(Infinity)).toThrow(ValidationError)
      expect(() => validateTimeout(-Infinity)).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout too short', () => {
      expect(() => validateTimeout(MIN_TIMEOUT_MS - 1)).toThrow(ValidationError)
      expect(() => validateTimeout(0)).toThrow(ValidationError)
      expect(() => validateTimeout(-1000)).toThrow(ValidationError)
    })

    it('should throw ValidationError for timeout too long', () => {
      expect(() => validateTimeout(MAX_TIMEOUT_MS + 1)).toThrow(ValidationError)
    })

    it('should return the timeout value when valid', () => {
      expect(validateTimeout(5000)).toBe(5000)
      expect(validateTimeout(MIN_TIMEOUT_MS)).toBe(MIN_TIMEOUT_MS)
      expect(validateTimeout(MAX_TIMEOUT_MS)).toBe(MAX_TIMEOUT_MS)
    })
  })

  describe('validateAuthenticationOptions', () => {
    it('should allow undefined options', () => {
      expect(() => validateAuthenticationOptions(undefined)).not.toThrow()
    })

    it('should allow empty options object', () => {
      expect(() => validateAuthenticationOptions({})).not.toThrow()
    })

    it('should allow valid promptMessage', () => {
      expect(() => validateAuthenticationOptions({ promptMessage: 'Authenticate' })).not.toThrow()
      expect(() => validateAuthenticationOptions({ promptMessage: 'Please authenticate' })).not.toThrow()
    })

    it('should throw ValidationError for non-string promptMessage', () => {
      expect(() => validateAuthenticationOptions({ promptMessage: 123 as any })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ promptMessage: null as any })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ promptMessage: {} as any })).toThrow(ValidationError)
    })

    it('should throw ValidationError for empty promptMessage', () => {
      expect(() => validateAuthenticationOptions({ promptMessage: '' })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ promptMessage: '   ' })).toThrow(ValidationError)
    })

    it('should allow valid cancelLabel', () => {
      expect(() => validateAuthenticationOptions({ cancelLabel: 'Cancel' })).not.toThrow()
      expect(() => validateAuthenticationOptions({ cancelLabel: 'Abort' })).not.toThrow()
    })

    it('should throw ValidationError for non-string cancelLabel', () => {
      expect(() => validateAuthenticationOptions({ cancelLabel: 123 as any })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ cancelLabel: null as any })).toThrow(ValidationError)
    })

    it('should throw ValidationError for empty cancelLabel', () => {
      expect(() => validateAuthenticationOptions({ cancelLabel: '' })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ cancelLabel: '   ' })).toThrow(ValidationError)
    })

    it('should allow valid disableDeviceFallback', () => {
      expect(() => validateAuthenticationOptions({ disableDeviceFallback: true })).not.toThrow()
      expect(() => validateAuthenticationOptions({ disableDeviceFallback: false })).not.toThrow()
    })

    it('should throw ValidationError for non-boolean disableDeviceFallback', () => {
      expect(() => validateAuthenticationOptions({ disableDeviceFallback: 'true' as any })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ disableDeviceFallback: 1 as any })).toThrow(ValidationError)
      expect(() => validateAuthenticationOptions({ disableDeviceFallback: null as any })).toThrow(ValidationError)
    })

    it('should allow all options together', () => {
      expect(() => validateAuthenticationOptions({
        promptMessage: 'Authenticate',
        cancelLabel: 'Cancel',
        disableDeviceFallback: true,
      })).not.toThrow()
    })

    it('should validate each option independently', () => {
      // Valid promptMessage, invalid cancelLabel
      expect(() => validateAuthenticationOptions({
        promptMessage: 'Authenticate',
        cancelLabel: '',
      })).toThrow(ValidationError)

      // Valid cancelLabel, invalid promptMessage
      expect(() => validateAuthenticationOptions({
        promptMessage: '',
        cancelLabel: 'Cancel',
      })).toThrow(ValidationError)
    })
  })
})


