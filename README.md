# @tetherto/wdk-rn-secure-storage

Secure storage abstractions for React Native - provides secure storage for sensitive data (encrypted seeds, keys) using react-native-keychain.

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

### Contributing

Since you're installing from source, you can:
1. Make changes to the code in `wdk-react-native-provider/wdk-rn-secure-storage`
2. Rebuild: `cd wdk-react-native-provider && npm run build`
3. The changes will be reflected in your app immediately (or after reinstalling)
4. Submit a pull request with your improvements!

## Peer Dependencies

```bash
npm install react-native@">=0.70.0"
```

## Usage

```typescript
import { SecureStorage } from '@tetherto/wdk-rn-secure-storage';

// Store sensitive data
await SecureStorage.setItem('key', 'sensitive-value');

// Retrieve data
const value = await SecureStorage.getItem('key');

// Remove data
await SecureStorage.removeItem('key');
```

## Features

- 🔒 Secure storage using native keychain/keystore
- 📱 iOS Keychain integration
- 🤖 Android Keystore integration
- 🔐 Biometric authentication support
- 💾 Encrypted data storage

## API

See [src/index.ts](./src/index.ts) for full API documentation.

## License

Apache-2.0
