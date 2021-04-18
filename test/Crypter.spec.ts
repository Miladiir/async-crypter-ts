import {expect} from "chai";
import {Crypter} from "../src/Crypter";
import {DecryptionError, EncryptionError} from "../src";

describe("Crypter", (): void => {

    const secret = "This is a very secure secret and I will get mad if you think otherwise.";
    const value = "Try to steal me. I dare you.";

    describe("constructor", (): void => {

        it("should accept non empty string", (): void => {

            expect(new Crypter(secret)).to.be.instanceOf(Crypter);
        });

        it("should not accept empty string", (): void => {

            expect(() => new Crypter("")).to.throw(Error);
        });

        it("should accept non empty Buffer", (): void => {

            expect(new Crypter(Buffer.from(secret))).to.be.instanceOf(Crypter);
        });

        it("should not accept empty Buffer", (): void => {

            expect(() => new Crypter(Buffer.alloc(0))).to.throw(Error);
        });

        it("should not accept anything else", (): void => {

            // @ts-expect-error Explicitly test incompatible types
            expect(() => new Crypter(null)).to.throw(Error);
            // @ts-expect-error Explicitly test incompatible types
            expect(() => new Crypter(undefined)).to.throw(Error);
            // @ts-expect-error Explicitly test incompatible types
            expect(() => new Crypter()).to.throw(Error);
            // @ts-expect-error Explicitly test incompatible types
            expect(() => new Crypter(0)).to.throw(Error);
        });
    });

    describe("encrypt", (): void => {

        it("should generate distinct output files (distinct instances)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter1 = new Crypter(secret);
            const crypter2 = new Crypter(secret);
            const encrypted1 = await crypter1.encrypt(buffer);
            const encrypted2 = await crypter2.encrypt(buffer);
            expect(encrypted1.toString()).to.not.equal(encrypted2.toString());
        });

        it("should generate distinct output files (same instance)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted1 = await crypter.encrypt(buffer);
            const encrypted2 = await crypter.encrypt(buffer);
            expect(encrypted1.toString()).to.not.equal(encrypted2.toString());
        });

        it("should work for an empty Buffer", async (): Promise<void> => {

            const buffer = Buffer.alloc(0);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            expect(encrypted.byteLength).to.be.at.least(64 + 16 + 16);
        });

        it("should fail for non Buffer values", async (): Promise<void> => {

            const crypter = new Crypter(secret);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt(123)).to.be.instanceOf(EncryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt("")).to.be.instanceOf(EncryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt(null)).to.be.instanceOf(EncryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt(undefined)).to.be.instanceOf(EncryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt()).to.be.instanceOf(EncryptionError);
        });

        it("should fail for empty Buffer aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const aad = Buffer.alloc(0);
            expect(await crypter.encrypt(buffer, aad)).to.be.instanceOf(EncryptionError);
        });

        it("should fail for any non Buffer type of aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt(buffer, 0)).to.be.instanceOf(EncryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.encrypt(buffer, new Date())).to.be.instanceOf(EncryptionError);
        });
    });

    describe("decrypt", (): void => {

        it("should be able to decrypt data (same class instance)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            const decrypted = await crypter.decrypt(encrypted);
            expect(buffer.toString()).to.equal(decrypted.toString());
        });

        it("should be able to decrypt data (same password)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter1 = new Crypter(secret);
            const encrypted = await crypter1.encrypt(buffer) as Buffer;
            const crypter2 = new Crypter(secret);
            const decrypted = await crypter2.decrypt(encrypted);
            expect(buffer.toString()).to.equal(decrypted.toString());
        });

        it("should fail for non Buffer values", async (): Promise<void> => {

            const crypter = new Crypter(secret);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt(123)).to.be.instanceOf(DecryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt("")).to.be.instanceOf(DecryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt(null)).to.be.instanceOf(DecryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt(undefined)).to.be.instanceOf(DecryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt()).to.be.instanceOf(DecryptionError);
        });

        it("should be able to decrypt data (same aad)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const additionalData = Buffer.from("Some additional data, like a userId, a random secret or something");
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer, additionalData) as Buffer;
            const decrypted = await crypter.decrypt(encrypted, additionalData);
            expect(buffer.toString()).to.equal(decrypted.toString());
        });

        it("should not be able to decrypt data with wrong password", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter1 = new Crypter(secret);
            const encrypted = await crypter1.encrypt(buffer) as Buffer;
            const wrongSecret = secret.replace("secure", "insecure");
            const crypter2 = new Crypter(wrongSecret);
            const decrypted = await crypter2.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with wrong aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const additionalData = Buffer.from("Some additional data, like a userId, a random secret or something");
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer, additionalData) as Buffer;
            const decrypted = await crypter.decrypt(encrypted, buffer);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with missing aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const additionalData = Buffer.from("Some additional data, like a userId, a random secret or something");
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer, additionalData) as Buffer;
            const decrypted = await crypter.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with aad when not encrypted using aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const additionalData = Buffer.from("Some additional data, like a userId, a random secret or something");
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            const decrypted = await crypter.decrypt(encrypted, additionalData);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with corrupted data (salt)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            encrypted.writeUInt8(0x00, 12);
            const decrypted = await crypter.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with corrupted data (iv)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            encrypted.writeUInt8(0x00, 64 + 3);
            const decrypted = await crypter.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with corrupted data (tag)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            encrypted.writeUInt8(0x00, 64 + 16 + 2);
            const decrypted = await crypter.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should not be able to decrypt data with corrupted data (data)", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            encrypted.writeUInt8(0x00, 64 + 16 + 16 + 12);
            const decrypted = await crypter.decrypt(encrypted);
            expect(decrypted).to.be.instanceOf(DecryptionError);
        });

        it("should fail for empty Buffer aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const aad = Buffer.alloc(0);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            expect(await crypter.decrypt(encrypted, aad)).to.be.instanceOf(DecryptionError);
        });

        it("should fail for any non Buffer type of aad", async (): Promise<void> => {

            const buffer = Buffer.from(value);
            const crypter = new Crypter(secret);
            const encrypted = await crypter.encrypt(buffer) as Buffer;
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt(encrypted, 0)).to.be.instanceOf(DecryptionError);
            // @ts-expect-error Explicitly test incompatible types
            expect(await crypter.decrypt(encrypted, new Date())).to.be.instanceOf(DecryptionError);
        })
    });
});