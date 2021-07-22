import {EncryptionError} from "./errors/EncryptionError";
import {ErrorMessage} from "./errors/ErrorMessage";
import {randomBytes} from "crypto";
import {DecryptionError} from "./errors/DecryptionError";
import {webcrypto} from "crypto";

const webcrypto1 = webcrypto as any;
const subtle = webcrypto1.subtle as SubtleCrypto;

/**
 * Performs AES-256-GCM encryption and decryption of buffers.
 * The encrypted buffers contain the salt (64 bytes), the iv (16 bytes), the encrypted value and, finally the tag (16 bytes)
 */
export class SubtleCrypter {

    /**
     * The algorithm in use.
     */
    private static readonly algorithm = 'AES-GCM';

    /**
     * The length of an initialization vector in bytes.
     */
    private static readonly ivLength = 16;

    /**
     * The length of a salt in bytes.
     */
    private static readonly saltLength = 64;

    /**
     * The length of an authentication tag in bits.
     */
    private static readonly tagLength = 128;

    /**
     * The offset of the authentication tag in bytes.
     */
    private static readonly encryptedPosition = SubtleCrypter.saltLength + SubtleCrypter.ivLength;

    /**
     * The secret used to encrypt and decrypt values by this instance.
     */
    readonly #secret: Buffer;

    /**
     * Initiate a new SubtleCrypter instance with the specified secret.
     * @param secret The secret used to encrypt and decrypt values.
     * @throws Error when passed anything but a non-empty string or Buffer.
     */
    public constructor(secret: string | Buffer) {

        if (secret instanceof Buffer && secret.length !== 0) {
            this.#secret = secret;
        } else if (typeof secret === "string" && secret.length !== 0) {
            this.#secret = Buffer.from(secret);
        } else {
            throw new Error(ErrorMessage.INVALID_SECRET);
        }
    }

    /**
     * Encrypt a buffer using AES256-GCM with a new generated salt and a random
     * initialization vector.
     * @param value The value to encrypt.
     * @param additionalAuthenticatedData Additional data that influences encryption outcome.
     * @returns The uniquely and symmetrically encrypted value.
     */
    public async encrypt(value: Buffer, additionalAuthenticatedData?: Buffer): Promise<Buffer | EncryptionError> {

        if (!(value instanceof Buffer)) {

            return new EncryptionError(ErrorMessage.INVALID_ENCRYPTION_VALUE);
        }
        const iv = randomBytes(SubtleCrypter.ivLength);
        const salt = randomBytes(SubtleCrypter.saltLength);
        const key = await this.generateKey(salt);
        if (additionalAuthenticatedData != null) {
            if (additionalAuthenticatedData instanceof Buffer && additionalAuthenticatedData.length !== 0) {
            } else {

                return new EncryptionError(ErrorMessage.INVALID_AAD);
            }
        }
        let result: Buffer;
        try {
            result = Buffer.from(await subtle.encrypt({
                name: SubtleCrypter.algorithm,
                iv,
                tagLength: SubtleCrypter.tagLength,
                additionalData: additionalAuthenticatedData
            }, key, value));
        } catch (e) {

            return new EncryptionError("Unknown error");
        }

        return Buffer.concat([salt, iv, result]);
    }

    /**
     * Decrypts a buffer containing the salt, initialization vector, tag and encrypted value.
     * @param value An encrypted value buffer.
     * @param additionalAuthenticatedData Additional data that was used to influence encryption outcome.
     * @returns The decrypted buffer containing the original value.
     */
    public async decrypt(value: Buffer, additionalAuthenticatedData?: Buffer): Promise<Buffer | DecryptionError> {

        if (!(value instanceof Buffer) || value.byteLength < SubtleCrypter.encryptedPosition) {

            return new DecryptionError(ErrorMessage.INVALID_DECRYPTION_VALUE);
        }

        const salt = value.slice(0, SubtleCrypter.saltLength);
        const key = await this.generateKey(salt);
        const iv = value.slice(SubtleCrypter.saltLength, SubtleCrypter.encryptedPosition);
        const encrypted = value.slice(SubtleCrypter.encryptedPosition);
        if (additionalAuthenticatedData != null) {
            if (additionalAuthenticatedData instanceof Buffer && additionalAuthenticatedData.length !== 0) {
            } else {

                return new DecryptionError(ErrorMessage.INVALID_AAD);
            }
        }
        let result: Buffer;
        try {
            result = Buffer.from(await subtle.decrypt({
                name: SubtleCrypter.algorithm,
                iv,
                tagLength: SubtleCrypter.tagLength,
                additionalData: additionalAuthenticatedData
            }, key, encrypted));
        } catch (e) {

            return new DecryptionError(ErrorMessage.DECRYPTION_FAILED);
        }

        return result;
    }

    /**
     * Generate an encryption key using the provided salt and the secret of the class.
     * @param salt A salt, either a new random sequence or stored in an encrypted buffer.
     * @returns An encryption key used to encrypt or decrypt a buffer.
     */
    private async generateKey(salt: Buffer): Promise<CryptoKey> {
        const key = await subtle.importKey("raw", this.#secret, "PBKDF2", false, ["deriveBits", "deriveKey"]);
        return subtle.deriveKey({
            name: "PBKDF2",
            iterations: 100000,
            hash: "SHA-512",
            salt
        }, key, {name: SubtleCrypter.algorithm, length: 256}, false, ["encrypt", "decrypt"]);
    }
}
