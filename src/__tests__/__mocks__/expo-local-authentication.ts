/**
 * Mock for expo-local-authentication
 * Used in tests to simulate authentication operations
 */

let mockIsEnrolled = true
let mockHasHardware = true
let mockAuthenticateResult = { success: true }

export function isEnrolledAsync(): Promise<boolean> {
  return Promise.resolve(mockIsEnrolled)
}

export function hasHardwareAsync(): Promise<boolean> {
  return Promise.resolve(mockHasHardware)
}

export function authenticateAsync(options?: {
  promptMessage?: string
  cancelLabel?: string
  disableDeviceFallback?: boolean
}): Promise<{ success: boolean }> {
  return Promise.resolve(mockAuthenticateResult)
}

// Helpers for tests to control mock behavior
export function __setMockIsEnrolled(value: boolean): void {
  mockIsEnrolled = value
}

export function __setMockHasHardware(value: boolean): void {
  mockHasHardware = value
}

export function __setMockAuthenticateResult(value: { success: boolean }): void {
  mockAuthenticateResult = value
}


