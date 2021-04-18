/**
 * String error messages for Crypter.
 */
export enum ErrorMessage {
    INVALID_ENCRYPTION_VALUE = "The value to encrypt is not a Buffer.",
    INVALID_DECRYPTION_VALUE = "The value to decrypt is not a Buffer or does not contain the full information necessary to perform the decryption.",
    INVALID_SECRET = "Invalid input for secret value. Must be a non-empty Buffer or string.",
    INVALID_AAD = "Invalid value for additional authenticated data. AAD must be a non-empty Buffer.",
    DECRYPTION_FAILED = "Decryption failed. Please check your secret, the additional authenticated data and the encrypted payload for errors."
}