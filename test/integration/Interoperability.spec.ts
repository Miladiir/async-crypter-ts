import {expect} from "chai";
import {Crypter} from "../../src";
import {SubtleCrypter} from "../../src/SubtleCrypter";

describe("Interoperability between implementations", () => {

    const secret = "This is a very secure secret and I will get mad if you think otherwise.";
    const value = "Try to steal me. I dare you.";

    it("should encrypt with Crypter and decrypt with SubtleCrypter", async () => {
        const crypter = new Crypter(secret);
        const subtleCrypter = new SubtleCrypter(secret);
        const encrypter = await crypter.encrypt(Buffer.from(value));
        if (encrypter instanceof Error) {
            expect.fail();
        }
        const decrypted = await subtleCrypter.decrypt(encrypter);
        expect(decrypted.toString()).to.equal(value);
    });

    it("should encrypt with SubtleCrypter and decrypt with Crypter", async () => {
        const crypter = new Crypter(secret);
        const subtleCrypter = new SubtleCrypter(secret);
        const encrypter = await subtleCrypter.encrypt(Buffer.from(value));
        if (encrypter instanceof Error) {
            expect.fail();
        }
        const decrypted = await crypter.decrypt(encrypter);
        expect(decrypted.toString()).to.equal(value);
    });
});
