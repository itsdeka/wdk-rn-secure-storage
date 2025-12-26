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

### Step 1: Clone the Repository

```bash
git clone https://github.com/itsdeka/wdk-rn-secure-storage.git
cd wdk-rn-secure-storage

# Install dependencies and build
npm install
npm run build
```

### Step 2: Install in Your App

From your app directory:

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

Creates a singleton instance of secure storage.

**Options:**
- `logger?: Logger` - Custom logger instance
- `authentication?: AuthenticationOptions` - Authentication prompt configuration
- `timeoutMs?: number` - Timeout for keychain operations (default: 30000ms)

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

## Security Features

### Input Validation
- All inputs are validated before processing
- Maximum length limits enforced (10KB for values, 256 chars for identifiers)
- Invalid characters rejected
- Type checking at runtime

### Rate Limiting
- Maximum 5 authentication attempts per 15-minute window
- 30-minute lockout after max attempts
- Per-identifier rate limiting

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

## Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## Security Considerations

- Data is encrypted at rest by iOS Keychain / Android Keystore
- Cloud sync enabled via iCloud Keychain (iOS) and Google Cloud backup (Android)
- Biometric authentication required when available
- Rate limiting prevents brute force attacks
- Input validation prevents injection attacks
- Storage keys are hashed to prevent collisions

## Contributing

Since you're installing from source, you can:
1. Make changes to the code in `wdk-react-native-provider/wdk-rn-secure-storage`
2. Rebuild: `cd wdk-react-native-provider && npm run build`
3. The changes will be reflected in your app immediately (or after reinstalling)
4. Submit a pull request with your improvements!

## License

Apache-2.0
