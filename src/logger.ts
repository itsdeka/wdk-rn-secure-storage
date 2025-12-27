/**
 * Log levels in order of severity
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

/**
 * Log entry structure
 */
export interface LogEntry {
  level: LogLevel
  message: string
  timestamp: number
  context?: Record<string, unknown>
  error?: Error
}

/**
 * Logger interface for structured logging
 */
export interface Logger {
  debug(message: string, context?: Record<string, unknown>): void
  info(message: string, context?: Record<string, unknown>): void
  warn(message: string, context?: Record<string, unknown>): void
  error(message: string, error?: Error, context?: Record<string, unknown>): void
  /**
   * Set the minimum log level
   * Logs below this level will be ignored
   */
  setLevel?(level: LogLevel): void
}

/**
 * Default logger implementation
 * Uses console methods but provides structured logging interface
 * 
 * **Default Log Level:** ERROR
 * 
 * The default log level is set to ERROR to minimize log noise in production.
 * This ensures that only critical errors are logged by default, which is appropriate
 * for production environments where excessive logging can impact performance and
 * expose sensitive information.
 * 
 * For development or debugging, you can change the log level:
 * ```typescript
 * defaultLogger.setLevel(LogLevel.DEBUG)
 * ```
 * 
 * For production monitoring of security events, consider setting to WARN:
 * ```typescript
 * defaultLogger.setLevel(LogLevel.WARN)
 * ```
 */
class DefaultLogger implements Logger {
  private minLevel: LogLevel = LogLevel.ERROR

  /**
   * Set the minimum log level
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level
  }

  /**
   * Internal log method
   */
  private log(
    level: LogLevel,
    message: string,
    error?: Error,
    context?: Record<string, unknown>
  ): void {
    if (level < this.minLevel) {
      return
    }

    const entry: LogEntry = {
      level,
      message,
      timestamp: Date.now(),
      context,
      error,
    }

    // In production, this could send to a logging service
    // For now, use console with structured output
    // Note: Sensitive data (encryption keys, seeds, etc.) should never be logged
    // The logger only logs error messages and metadata, never the actual stored values
    const logMessage = JSON.stringify(entry, null, 2)

    if (level >= LogLevel.ERROR) {
      console.error(logMessage)
    } else if (level >= LogLevel.WARN) {
      console.warn(logMessage)
    } else {
      console.log(logMessage)
    }
  }

  debug(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.DEBUG, message, undefined, context)
  }

  info(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.INFO, message, undefined, context)
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.log(LogLevel.WARN, message, undefined, context)
  }

  error(message: string, error?: Error, context?: Record<string, unknown>): void {
    this.log(LogLevel.ERROR, message, error, context)
  }
}

/**
 * Default logger instance
 */
export const defaultLogger = new DefaultLogger()

