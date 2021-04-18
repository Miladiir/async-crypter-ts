import {createCipheriv, createDecipheriv, pbkdf2, randomBytes} from "crypto";
import {promisify} from "util";
import {EncryptionError} from "./errors/EncryptionError";
import {ErrorMessage} from "./errors/ErrorMessage";
import {DecryptionError} from "./errors/DecryptionError";

/**
 * Performs AES-256-GCM encryption and decryption of buffers.
 * The encrypted buffers contain the salt (64 bytes), the iv (16 bytes), the tag (16 bytes)
 * and finally the encrypted value (rest of the buffer).
 */
export class Crypter {

    /**
     * The algorithm in use.
     */
    private static readonly algorithm = 'aes-256-gcm';

    /**
     * The length of an initialization vector in bytes.
     */
    private static readonly ivLength = 16;

    /**
     * The length of a salt in bytes.
     */
    private static readonly saltLength = 64;

    /**
     * The length of an authentication tag in bytes.
     */
    private static readonly tagLength = 16;

    /**
     * The offset of the authentication tag in bytes.
     */
    private static readonly tagPosition = Crypter.saltLength + Crypter.ivLength;

    /**
     * The offset of the encrypted value in bytes.
     */
    private static readonly encryptedPosition = Crypter.tagPosition + Crypter.tagLength;

    /**
     * Promisified crypto.pbkdf2
     */
    private static readonly pbkdf2 = promisify(pbkdf2);

    /**
     * The secret used to encrypt and decrypt values by this instance.
     */
    readonly #secret: Buffer;

    /**
     * Initiate a new Crypter instance with the specified secret.
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
        const iv = randomBytes(Crypter.ivLength);
        const salt = randomBytes(Crypter.saltLength);
        const key = await this.generateKey(salt);
        const cipher = createCipheriv(Crypter.algorithm, key, iv);
        if (additionalAuthenticatedData != null) {
            if (additionalAuthenticatedData instanceof Buffer && additionalAuthenticatedData.length !== 0) {
                cipher.setAAD(additionalAuthenticatedData);
            } else {

                return new EncryptionError(ErrorMessage.INVALID_AAD);
            }
        }
        let updatedBuffer, finalBuffer, authTag: Buffer;
        try {
            updatedBuffer = cipher.update(value);
            finalBuffer = cipher.final();
            authTag = cipher.getAuthTag();
        } catch (e) {

            return new EncryptionError("Unknown error");
        }

        return Buffer.concat([salt, iv, authTag, updatedBuffer, finalBuffer]);
    }

    /**
     * Decrypts a buffer containing the salt, initialization vector, tag and encrypted value.
     * @param value An encrypted value buffer.
     * @param additionalAuthenticatedData Additional data that was used to influence encryption outcome.
     * @returns The decrypted buffer containing the original value.
     */
    public async decrypt(value: Buffer, additionalAuthenticatedData?: Buffer): Promise<Buffer | DecryptionError> {

        if (!(value instanceof Buffer) || value.byteLength < Crypter.encryptedPosition) {

            return new DecryptionError(ErrorMessage.INVALID_DECRYPTION_VALUE);
        }

        const salt = value.slice(0, Crypter.saltLength);
        const key = await this.generateKey(salt);
        const iv = value.slice(Crypter.saltLength, Crypter.tagPosition);
        const tag = value.slice(Crypter.tagPosition, Crypter.encryptedPosition);
        const encrypted = value.slice(Crypter.encryptedPosition);
        const decipher = createDecipheriv(Crypter.algorithm, key, iv);
        if (additionalAuthenticatedData != null) {
            if (additionalAuthenticatedData instanceof Buffer && additionalAuthenticatedData.length !== 0) {
                decipher.setAAD(additionalAuthenticatedData);
            } else {

                return new DecryptionError(ErrorMessage.INVALID_AAD);
            }
        }
        decipher.setAuthTag(tag);
        let updatedBuffer, finalBuffer: Buffer;
        try {
            updatedBuffer = decipher.update(encrypted);
            finalBuffer = decipher.final();
        } catch (e) {

            return new DecryptionError(ErrorMessage.DECRYPTION_FAILED);
        }

        return Buffer.concat([updatedBuffer, finalBuffer]);
    }

    /**
     * Generate an encryption key using the provided salt and the secret of the class.
     * @param salt A salt, either a new random sequence or stored in an encrypted buffer.
     * @returns An encryption key used to encrypt or decrypt a buffer.
     */
    private generateKey(salt: Buffer): Promise<Buffer> {

        return Crypter.pbkdf2(this.#secret, salt, 100000, 32, 'sha512');
    }
}