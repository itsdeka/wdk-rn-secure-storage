import { defaultLogger, LogLevel } from '../logger'

describe('logger', () => {
  let consoleErrorSpy: jest.SpyInstance
  let consoleWarnSpy: jest.SpyInstance
  let consoleLogSpy: jest.SpyInstance

  beforeEach(() => {
    // Spy on console methods
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation()
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation()
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation()
  })

  afterEach(() => {
    // Restore console methods
    consoleErrorSpy.mockRestore()
    consoleWarnSpy.mockRestore()
    consoleLogSpy.mockRestore()
    // Reset logger level to default (ERROR)
    defaultLogger.setLevel(LogLevel.ERROR)
  })

  describe('defaultLogger', () => {
    it('should set log level', () => {
      defaultLogger.setLevel(LogLevel.DEBUG)
      expect(() => defaultLogger.setLevel(LogLevel.INFO)).not.toThrow()
    })

    it('should log error messages', () => {
      defaultLogger.setLevel(LogLevel.ERROR)
      const error = new Error('Test error')
      defaultLogger.error('Error message', error, { context: 'test' })
      
      expect(consoleErrorSpy).toHaveBeenCalledTimes(1)
      const logCall = consoleErrorSpy.mock.calls[0][0]
      expect(logCall).toContain('Error message')
      expect(JSON.parse(logCall)).toMatchObject({
        level: LogLevel.ERROR,
        message: 'Error message',
      })
    })

    it('should log warn messages when level is WARN or lower', () => {
      defaultLogger.setLevel(LogLevel.WARN)
      defaultLogger.warn('Warning message', { context: 'test' })
      
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1)
      const logCall = consoleWarnSpy.mock.calls[0][0]
      expect(JSON.parse(logCall)).toMatchObject({
        level: LogLevel.WARN,
        message: 'Warning message',
      })
    })

    it('should log info messages when level is INFO or lower', () => {
      defaultLogger.setLevel(LogLevel.INFO)
      defaultLogger.info('Info message', { context: 'test' })
      
      expect(consoleLogSpy).toHaveBeenCalledTimes(1)
      const logCall = consoleLogSpy.mock.calls[0][0]
      expect(JSON.parse(logCall)).toMatchObject({
        level: LogLevel.INFO,
        message: 'Info message',
      })
    })

    it('should log debug messages when level is DEBUG', () => {
      defaultLogger.setLevel(LogLevel.DEBUG)
      defaultLogger.debug('Debug message', { context: 'test' })
      
      expect(consoleLogSpy).toHaveBeenCalledTimes(1)
      const logCall = consoleLogSpy.mock.calls[0][0]
      expect(JSON.parse(logCall)).toMatchObject({
        level: LogLevel.DEBUG,
        message: 'Debug message',
      })
    })

    it('should not log messages below minimum level', () => {
      defaultLogger.setLevel(LogLevel.ERROR)
      
      defaultLogger.debug('Debug message')
      defaultLogger.info('Info message')
      defaultLogger.warn('Warning message')
      
      expect(consoleLogSpy).not.toHaveBeenCalled()
      expect(consoleWarnSpy).not.toHaveBeenCalled()
      
      // Error should still be logged
      defaultLogger.error('Error message')
      expect(consoleErrorSpy).toHaveBeenCalledTimes(1)
    })

    it('should include context in log entries', () => {
      defaultLogger.setLevel(LogLevel.DEBUG)
      defaultLogger.info('Test message', { key: 'value', number: 123 })
      
      const logCall = consoleLogSpy.mock.calls[0][0]
      const entry = JSON.parse(logCall)
      expect(entry.context).toEqual({ key: 'value', number: 123 })
    })

    it('should include error in log entries', () => {
      defaultLogger.setLevel(LogLevel.ERROR)
      const error = new Error('Test error')
      error.stack = 'Error stack trace'
      
      defaultLogger.error('Error message', error)
      
      const logCall = consoleErrorSpy.mock.calls[0][0]
      const entry = JSON.parse(logCall)
      expect(entry.error).toBeDefined()
    })

    it('should include timestamp in log entries', () => {
      defaultLogger.setLevel(LogLevel.DEBUG)
      const beforeTime = Date.now()
      
      defaultLogger.info('Test message')
      
      const logCall = consoleLogSpy.mock.calls[0][0]
      const entry = JSON.parse(logCall)
      const afterTime = Date.now()
      
      expect(entry.timestamp).toBeGreaterThanOrEqual(beforeTime)
      expect(entry.timestamp).toBeLessThanOrEqual(afterTime)
    })
  })
})

