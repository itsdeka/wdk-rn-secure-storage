# @tetherto/wdk-rn-secure-storage

Secure storage abstractions for React Native - provides secure storage for sensitive data (encrypted seeds, keys) using react-native-keychain.

## Features

- 🔒 Secure storage using native keychain/keystore
- 📱 iOS Keychain integration with iCloud sync
- 🤖 Android Keystore integration with Google Cloud backup
- 🔐 Biometric authentication support
- 💾 Encrypted data storage at rest
- 🛡️ Rate limiting to prevent brute force attacks
- ✅ Comprehensive input validation
- 📊 Structured logging support
- ⏱️ Configurable timeouts
- 🎯 TypeScript support with full type safety

## Installation

### From npm (Recommended for Production)

```bash
npm install @tetherto/wdk-rn-secure-storage
```

### From GitHub (Development/Unpublished Versions)

If the package is not yet published to npm, you can install directly from GitHub:

```bash
npm install https://github.com/itsdeka/wdk-rn-secure-storage.git
```

Or add to your `package.json`:

```json
{
  "dependencies": {
    "@tetherto/wdk-rn-secure-storage": "github:itsdeka/wdk-rn-secure-storage"
  }
}
```

Then run `npm install`.

## Peer Dependencies

```bash
npm install react-native@">=0.70.0"
```

## ⚠️ Important Security Notice

**Rate Limiting Reset on App Restart:** The rate limiting mechanism resets when the app is restarted. This means an attacker could potentially bypass rate limiting by restarting the app. However, this is generally acceptable for mobile apps because:

- Restarting requires user interaction (not easily automated)
- OS-level keychain/keystore protections still apply
- App-level rate limiting provides defense-in-depth within a session

For high-security scenarios requiring persistent rate limiting across app restarts, consider implementing a wrapper that stores rate limit state in secure storage. See the [Rate Limiting](#rate-limiting) section for details.

## Usage

### Basic Usage

```typescript
import { createSecureStorage } from '@tetherto/wdk-rn-secure-storage'

// Create storage instance
const storage = createSecureStorage()

// Store encryption key
await storage.setEncryptionKey('my-encryption-key', 'user@example.com')

// Retrieve encryption key
const key = await storage.getEncryptionKey('user@example.com')
if (key) {
  console.log('Key retrieved:', key)
}

// Store encrypted seed
await storage.setEncryptedSeed('encrypted-seed-data', 'user@example.com')

// Store encrypted entropy
await storage.setEncryptedEntropy('encrypted-entropy-data', 'user@example.com')

// Get all encrypted data
const allData = await storage.getAllEncrypted('user@example.com')
console.log('All data:', allData)

// Check if wallet exists
const exists = await storage.hasWallet('user@example.com')

// Delete wallet
await storage.deleteWallet('user@example.com')
```

### Advanced Usage with Options

```typescript
import { createSecureStorage, defaultLogger, LogLevel } from '@tetherto/wdk-rn-secure-storage'

// Configure logger
defaultLogger.setLevel(LogLevel.INFO)

// Create storage with custom options
const storage = createSecureStorage({
  logger: customLogger, // Optional custom logger
  authentication: {
    promptMessage: 'Authenticate to access your wallet',
    cancelLabel: 'Cancel',
    disableDeviceFallback: false,
  },
  timeoutMs: 30000, // 30 seconds default
})

// Use storage
await storage.setEncryptionKey('key', 'user@example.com')
```

### Error Handling

```typescript
import {
  createSecureStorage,
  ValidationError,
  KeychainWriteError,
  KeychainReadError,
  AuthenticationError,
  TimeoutError,
} from '@tetherto/wdk-rn-secure-storage'

const storage = createSecureStorage()

try {
  await storage.setEncryptionKey('my-key', 'user@example.com')
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Invalid input:', error.message)
  } else if (error instanceof KeychainWriteError) {
    console.error('Failed to write to keychain:', error.message)
  } else if (error instanceof TimeoutError) {
    console.error('Operation timed out:', error.message)
  } else {
    console.error('Unexpected error:', error)
  }
}

try {
  const key = await storage.getEncryptionKey('user@example.com')
  if (!key) {
    console.log('Key not found')
  }
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message)
  } else if (error instanceof KeychainReadError) {
    console.error('Failed to read from keychain:', error.message)
  }
}
```

### Multiple Wallets

The identifier parameter allows you to support multiple wallets:

```typescript
// Store data for different users
await storage.setEncryptionKey('key1', 'user1@example.com')
await storage.setEncryptionKey('key2', 'user2@example.com')

// Retrieve specific user's data
const key1 = await storage.getEncryptionKey('user1@example.com')
const key2 = await storage.getEncryptionKey('user2@example.com')
```

## API Reference

### `createSecureStorage(options?)`

Creates a new instance of secure storage. Each call returns a new instance with the specified options.
For most apps, you should create one instance and reuse it throughout your application.

**Options:**
- `logger?: Logger` - Custom logger instance
- `authentication?: AuthenticationOptions` - Authentication prompt configuration
- `timeoutMs?: number` - Timeout for keychain operations (default: 30000ms, min: 1000ms, max: 300000ms)

**Returns:** `SecureStorage` instance

### `SecureStorage` Interface

#### `setEncryptionKey(key: string, identifier?: string): Promise<void>`

Stores an encryption key securely.

**Parameters:**
- `key: string` - The encryption key (max 10KB, non-empty)
- `identifier?: string` - Optional identifier for multiple wallets (max 256 chars)

**Throws:**
- `ValidationError` - If input is invalid
- `KeychainWriteError` - If keychain operation fails
- `TimeoutError` - If operation times out

#### `getEncryptionKey(identifier?: string): Promise<string | null>`

Retrieves an encryption key.

**Parameters:**
- `identifier?: string` - Optional identifier

**Returns:** The encryption key or `null` if not found

**Throws:**
- `ValidationError` - If identifier is invalid
- `AuthenticationError` - If authentication fails or rate limit exceeded
- `KeychainReadError` - If keychain operation fails
- `TimeoutError` - If operation times out

#### `setEncryptedSeed(encryptedSeed: string, identifier?: string): Promise<void>`

Stores encrypted seed data.

#### `getEncryptedSeed(identifier?: string): Promise<string | null>`

Retrieves encrypted seed data.

#### `setEncryptedEntropy(encryptedEntropy: string, identifier?: string): Promise<void>`

Stores encrypted entropy data.

#### `getEncryptedEntropy(identifier?: string): Promise<string | null>`

Retrieves encrypted entropy data.

#### `getAllEncrypted(identifier?: string): Promise<{encryptedSeed: string | null, encryptedEntropy: string | null, encryptionKey: string | null}>`

Retrieves all encrypted wallet data at once.

#### `hasWallet(identifier?: string): Promise<boolean>`

Checks if wallet credentials exist.

#### `deleteWallet(identifier?: string): Promise<void>`

Deletes all wallet credentials.

**Throws:**
- `ValidationError` - If identifier is invalid
- `SecureStorageError` - If deletion fails (with details of which items failed)
- `TimeoutError` - If operation times out

#### `isBiometricAvailable(): Promise<boolean>`

Checks if biometric authentication is available.

#### `authenticate(): Promise<boolean>`

Authenticates with biometrics. Returns `true` if successful, `false` otherwise.

**Throws:**
- `AuthenticationError` - If rate limit exceeded

### `cleanupSecureStorageModule()`

Cleans up module resources (rate limiting state and periodic cleanup interval).

**Important Notes:**
- This does NOT delete stored wallet data - use `deleteWallet()` for that.
- This is typically only needed in specific scenarios (hot-reload, testing, app shutdown)
- For normal app usage, you generally don't need to call this manually
- The module automatically cleans up expired rate limit entries periodically

**When to call:**
- During hot-reload in development (to reset rate limiting state)
- In test teardown (to ensure clean state between tests)
- During app shutdown (optional, for explicit cleanup)
- When you want to reset rate limiting state programmatically

**Examples:**

```typescript
import { cleanupSecureStorageModule } from '@tetherto/wdk-rn-secure-storage'

// Example 1: In test teardown
afterAll(() => {
  cleanupSecureStorageModule()
})

// Example 2: During hot-reload (development only)
if (__DEV__ && module.hot) {
  module.hot.dispose(() => {
    cleanupSecureStorageModule()
  })
}

// Example 3: In React Native app lifecycle (optional)
import { AppState } from 'react-native'

AppState.addEventListener('change', (nextAppState) => {
  if (nextAppState === 'background') {
    // Optional: cleanup when app goes to background
    // Note: This is usually not necessary for normal usage
  }
})
```

### Logger Interface

The module provides a `Logger` interface for structured logging. The default logger can be configured:

```typescript
import { defaultLogger, LogLevel } from '@tetherto/wdk-rn-secure-storage'

// Set the minimum log level (logs below this level will be ignored)
defaultLogger.setLevel(LogLevel.INFO)

// Available log levels: DEBUG, INFO, WARN, ERROR
```

You can also provide a custom logger that implements the `Logger` interface:

```typescript
const customLogger: Logger = {
  debug: (message, context) => { /* ... */ },
  info: (message, context) => { /* ... */ },
  warn: (message, context) => { /* ... */ },
  error: (message, error, context) => { /* ... */ },
  setLevel: (level) => { /* optional */ },
}

const storage = createSecureStorage({ logger: customLogger })
```

## Module Lifecycle & Resource Management

### Cleanup API

The module provides a cleanup function to release resources when no longer needed:

```typescript
import { cleanupSecureStorageModule } from '@tetherto/wdk-rn-secure-storage'

// In your app's cleanup lifecycle (e.g., app shutdown, hot-reload)
cleanupSecureStorageModule()
```

**Important Notes:**
- This stops the periodic cleanup interval and clears rate limiting state
- This does NOT delete stored wallet data - use `deleteWallet()` for that
- In most cases, you don't need to call this manually
- Useful for hot-reload scenarios or when you want to reset rate limiting state

### Shared Rate Limiting State

**Important:** Rate limiting is shared across ALL storage instances. This means:
- All instances created with `createSecureStorage()` share the same rate limit state
- Rate limiting is global, not per-instance
- This provides consistent security behavior across your application

### Module Initialization

The module uses lazy initialization to avoid side effects on import:
- Periodic cleanup starts automatically on first rate limit check
- No side effects when the module is imported
- Makes testing easier and prevents issues in test environments

## Security Features

### Input Validation
- All inputs are validated before processing
- Maximum length limits enforced (10KB for values, 256 chars for identifiers)
- Invalid characters rejected
- Type checking at runtime
- All validation happens before any side effects

### Rate Limiting

**⚠️ Security Limitation:** Rate limiting state is stored in-memory only and **resets when the app is restarted**. This is a known limitation that should be considered for high-security applications.

**Current Behavior:**
- Maximum 5 authentication attempts per 15-minute window
- 30-minute lockout after max attempts
- Per-identifier rate limiting
- **Shared state:** Rate limiting is global across all storage instances
- **In-memory storage:** Rate limiting state is stored in memory and resets on app restart

**Why This Is Generally Acceptable:**
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>
read_file

1. **User Interaction Required**: Restarting a mobile app requires user interaction, making it difficult for attackers to rapidly restart and bypass rate limits
2. **OS-Level Protections**: The underlying keychain/keystore has its own rate limiting and lockout mechanisms
3. **Defense in Depth**: App-level rate limiting adds an additional layer of protection on top of OS-level protections

However, for high-security scenarios where persistent rate limiting across app restarts is required, you may want to implement persistent rate limiting using secure storage. This would involve:

- Storing rate limit state in secure storage (encrypted)
- Checking and updating rate limit state on each authentication attempt
- Implementing proper cleanup of expired rate limit entries

**Security Implications:**
- **In-Memory (Current)**: Resets on app restart, but prevents rapid-fire authentication attempts within a session
- **Persistent (Future)**: Survives app restarts, providing stronger protection but requiring secure storage for rate limit state

If you need persistent rate limiting for your use case, consider implementing it as a wrapper around this module that stores rate limit state in secure storage.

### Error Handling
- Comprehensive error types for different failure scenarios
- Detailed error messages
- Proper error propagation

### Logging
- Structured logging for security events
- Configurable log levels
- No sensitive data in logs

## Error Types

- `SecureStorageError` - Base error class
- `KeychainError` - Keychain operation errors
- `KeychainWriteError` - Keychain write failures
- `KeychainReadError` - Keychain read failures
- `AuthenticationError` - Authentication failures
- `ValidationError` - Input validation failures
- `TimeoutError` - Operation timeout errors

## Development

### Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Code Quality

```bash
# Type checking
npm run typecheck

# Linting
npm run lint
npm run lint:fix

# Formatting
npm run format
npm run format:check
```

**Note:** ESLint and Prettier are configured but need to be installed as dev dependencies:
```bash
npm install --save-dev eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin prettier
```

## Production Readiness

This module is production-ready and includes:

✅ **Built and tested** - All code is compiled to JavaScript with TypeScript definitions  
✅ **Proper exports** - Only necessary files are included in the npm package  
✅ **Security hardened** - Input validation, rate limiting, and secure storage  
✅ **Error handling** - Comprehensive error types for all failure scenarios  
✅ **Logging** - Structured logging with configurable levels (defaults to ERROR in production)  
✅ **Type safety** - Full TypeScript support with exported types  
✅ **Documentation** - Complete API documentation and usage examples  

### Production Best Practices

1. **Configure Logging**: Set appropriate log levels for your environment:
   ```typescript
   import { defaultLogger, LogLevel } from '@tetherto/wdk-rn-secure-storage'
   
   // In production, only log errors and warnings
   defaultLogger.setLevel(LogLevel.WARN)
   
   // In development, you might want more verbose logging
   if (__DEV__) {
     defaultLogger.setLevel(LogLevel.DEBUG)
   }
   ```

2. **Error Handling**: Always handle errors appropriately:
   ```typescript
   try {
     await storage.setEncryptionKey(key, identifier)
   } catch (error) {
     // Log error to your error tracking service (e.g., Sentry)
     // Never log sensitive data like keys or seeds
     if (error instanceof ValidationError) {
       // Handle validation errors
     } else if (error instanceof KeychainWriteError) {
       // Handle keychain errors
     }
   }
   ```

3. **Single Instance**: Create one storage instance and reuse it:
   ```typescript
   // Good: Create once and reuse
   const storage = createSecureStorage({ logger: customLogger })
   
   // Avoid: Creating multiple instances unnecessarily
   ```

## Security Considerations

- Data is encrypted at rest by iOS Keychain / Android Keystore
- Cloud sync enabled via iCloud Keychain (iOS) and Google Cloud backup (Android)
- Biometric authentication required when available
- Rate limiting prevents brute force attacks
- Input validation prevents injection attacks
- Storage keys are hashed to prevent collisions
- **No sensitive data is logged** - The logger only logs error messages and metadata

## Security Limitations

⚠️ **Important Security Notes:**

1. **Rate Limiting Reset on App Restart**: Rate limiting state is stored in-memory only and resets when the app is restarted. This means an attacker could potentially bypass rate limiting by restarting the app. However, this is generally acceptable for mobile apps where:
   - Restarting requires user interaction
   - The app is typically running in the foreground during authentication
   - The device itself provides additional security layers (device lock, biometrics)

   For enhanced security in high-risk scenarios, consider implementing persistent rate limiting using secure storage or AsyncStorage.

2. **Timeout Resource Usage**: The timeout implementation uses `Promise.race()` which does NOT cancel the underlying keychain operation. The operation continues executing even after timeout, though its result is ignored. This means:
   - Under extreme load, timed-out keychain operations may continue executing in the background
   - Memory and resources are not immediately freed on timeout
   - This is generally acceptable because:
     - Keychain operations are typically fast (< 1 second)
     - They are bounded in duration by the OS
     - Timeouts are a safety mechanism, not a normal occurrence
     - React Native's single-threaded nature limits concurrent operations
   - **Monitoring**: In production, monitor timeout frequency. If timeouts occur frequently, investigate keychain performance or increase timeout values.

3. **In-Memory Rate Limiter**: The rate limiter uses an in-memory Map that automatically cleans up expired entries. However, if many unique identifiers are used, memory usage may grow. The implementation includes automatic cleanup to mitigate this. **Shared State**: Rate limiting is shared across all storage instances - this is intentional and provides consistent security behavior.

4. **Device Authentication**: On devices without authentication (no PIN/password/biometrics), data is still encrypted at rest but accessible when the device is unlocked. This is a limitation of the underlying platform security model.

5. **Module Cleanup**: The module uses lazy initialization to avoid side effects on import. Periodic cleanup starts automatically on first rate limit check. For hot-reload scenarios or explicit cleanup, use `cleanupSecureStorageModule()`.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`npm test`)
5. Run type checking (`npm run typecheck`)
6. Run linting (`npm run lint`)
7. Format code (`npm run format`)
8. Build the project (`npm run build`)
9. Commit your changes (`git commit -m 'Add amazing feature'`)
10. Push to the branch (`git push origin feature/amazing-feature`)
11. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/itsdeka/wdk-rn-secure-storage.git
cd wdk-rn-secure-storage

# Install dependencies
npm install

# Run tests
npm test

# Run type checking
npm run typecheck

# Run linting
npm run lint

# Format code
npm run format

# Build
npm run build
```

## License

Apache-2.0
