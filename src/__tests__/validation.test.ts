import { validateIdentifier, validateValue, MAX_IDENTIFIER_LENGTH, MAX_VALUE_LENGTH } from '../validation'
import { ValidationError } from '../errors'

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
})


