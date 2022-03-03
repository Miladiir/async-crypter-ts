import {expect} from "chai";
import {Crypter} from "../../src";
import {SubtleCrypter} from "../../src/SubtleCrypter";
import {Crypto} from "@peculiar/webcrypto";
import semver from "semver";
import {webcrypto} from "crypto";

before(() => {
    let crypto;
    if (semver.gte(process.version, '15.0.0')) {
        console.info("Using nodejs webcrypto");
        crypto = webcrypto
    } else {
        console.info("Using peculiar webcrypto")
        crypto = new Crypto();
    }
    // @ts-ignore
    global.crypto = crypto;
});

describe("Interoperability between implementations", () => {

    const secret = "This is a very secure secret and I will get mad if you think otherwise.";
    const value = "Try to steal me. I dare you.";

    it("should encrypt with Crypter and decrypt with SubtleCrypter", async () => {
        const crypter = new Crypter(secret);
        const subtleCrypter = new SubtleCrypter(secret);
        const encrypted = await crypter.encrypt(Buffer.from(value));
        if (encrypted instanceof Error) {
            expect.fail();
        }
        const decrypted = await subtleCrypter.decrypt(encrypted);
        if (decrypted instanceof Error) {
            expect.fail()
        }
        expect(Buffer.from(decrypted).toString()).to.equal(value);
    });

    it("should encrypt with SubtleCrypter and decrypt with Crypter", async () => {
        const crypter = new Crypter(secret);
        const subtleCrypter = new SubtleCrypter(secret);
        const encrypted = await subtleCrypter.encrypt(Buffer.from(value));
        if (encrypted instanceof Error) {
            expect.fail();
        }
        const decrypted = await crypter.decrypt(Buffer.from(encrypted));
        if (decrypted instanceof Error) {
            expect.fail()
        }
        expect(Buffer.from(decrypted).toString()).to.equal(value);
    });
});

after(() => {
    // @ts-ignore
    delete global.crypto;
})