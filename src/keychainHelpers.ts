import * as Keychain from 'react-native-keychain'

/**
 * Keychain options for setGenericPassword
 */
export type KeychainOptions = Parameters<typeof Keychain.setGenericPassword>[2]

/**
 * Create keychain options with conditional access control
 * 
 * @param deviceAuthAvailable - Whether device authentication (biometrics/PIN) is available
 * @param requireAuth - Whether authentication should be required for this operation
 * @param syncable - Whether the value should sync across devices (default: true)
 * @returns Keychain options object with appropriate access control settings
 */
export function createKeychainOptions(
  deviceAuthAvailable: boolean,
  requireAuth: boolean = true,
  syncable: boolean = true
): KeychainOptions {
  const options: KeychainOptions = {
    accessible: syncable 
      ? Keychain.ACCESSIBLE.WHEN_UNLOCKED 
      : Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  }
  
  if (requireAuth && deviceAuthAvailable) {
    options.accessControl = Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
  }
  
  return options
}


