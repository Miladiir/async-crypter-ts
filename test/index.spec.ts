import {Crypter as CrypterA} from "../src";
import CrypterB from "../src";
import {expect} from "chai";

describe("index", (): void => {

    it("should be the same imported module", (): void => {

        expect(CrypterA).to.equal(CrypterB);
    });
});