# @tetherto/wdk-rn-secure-storage

Secure storage abstractions for React Native - provides secure storage for sensitive data (encrypted seeds, keys) using react-native-keychain.

## Features

- 🔒 Secure storage using native keychain/keystore
- 📱 iOS Keychain integration with selective iCloud sync
- 🤖 Android Keystore integration with selective Google Cloud backup
- 🔐 Biometric authentication support
- 💾 Encrypted data storage at rest
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
- `AuthenticationError` - If authentication fails
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
- `AuthenticationError` - If authentication fails


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

The module has no shared state or cleanup requirements. Each storage instance is independent and can be used without any module-level lifecycle management.

## Security Features

### Input Validation
- All inputs are validated before processing
- Maximum length limits enforced (10KB for values, 256 chars for identifiers)
- Invalid characters rejected
- Type checking at runtime
- All validation happens before any side effects

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
✅ **Security hardened** - Input validation and secure storage with device-level protections  
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
- Cloud sync behavior:
  - **Encryption key**: Synced via iCloud Keychain (iOS) and Google Cloud backup (Android)
  - **Encrypted seed and entropy**: Device-only storage (not synced across devices)
- Biometric authentication required when available
- Device-level keychain/keystore provides rate limiting and lockout mechanisms
- **No sensitive data is logged** - The logger only logs error messages and metadata

## Security Limitations

⚠️ **Important Security Notes:**

1. **Timeout Resource Usage**: The timeout implementation uses `Promise.race()` which does NOT cancel the underlying keychain operation. The operation continues executing even after timeout, though its result is ignored. This means:
   - Under extreme load, timed-out keychain operations may continue executing in the background
   - Memory and resources are not immediately freed on timeout
   - This is generally acceptable because:
     - Keychain operations are typically fast (< 1 second)
     - They are bounded in duration by the OS
     - Timeouts are a safety mechanism, not a normal occurrence
     - React Native's single-threaded nature limits concurrent operations
   - **Monitoring**: In production, monitor timeout frequency. If timeouts occur frequently, investigate keychain performance or increase timeout values.

2. **Device Authentication**: On devices without authentication (no PIN/password/biometrics), data is still encrypted at rest but accessible when the device is unlocked. This is a limitation of the underlying platform security model.

3. **Device-Level Rate Limiting**: The module relies on device-level keychain/keystore rate limiting and lockout mechanisms. These are more robust than app-level rate limiting and persist across app restarts.

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
