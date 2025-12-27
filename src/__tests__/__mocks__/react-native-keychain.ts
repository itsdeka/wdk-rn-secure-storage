/**
 * Mock for react-native-keychain
 * Used in tests to simulate keychain operations
 */

export const ACCESSIBLE = {
  WHEN_UNLOCKED: 'WHEN_UNLOCKED',
}

export const ACCESS_CONTROL = {
  BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BIOMETRY_ANY_OR_DEVICE_PASSCODE',
}

let mockStorage: Map<string, { username: string; password: string }> = new Map()

export function setGenericPassword(
  username: string,
  password: string,
  options?: { service?: string }
): Promise<{ service: string; storage: string } | false> {
  const service = options?.service || 'default'
  mockStorage.set(service, { username, password })
  return Promise.resolve({ service, storage: 'keychain' })
}

export function getGenericPassword(options?: { service?: string }): Promise<
  | {
      service: string
      username: string
      password: string
      storage: string
    }
  | false
> {
  const service = options?.service || 'default'
  const stored = mockStorage.get(service)
  if (stored) {
    return Promise.resolve({
      service,
      username: stored.username,
      password: stored.password,
      storage: 'keychain',
    })
  }
  return Promise.resolve(false)
}

export function resetGenericPassword(options?: { service?: string }): Promise<boolean> {
  const service = options?.service || 'default'
  mockStorage.delete(service)
  return Promise.resolve(true)
}

// Helper for tests to reset mock storage
export function __resetMockStorage(): void {
  mockStorage.clear()
}


