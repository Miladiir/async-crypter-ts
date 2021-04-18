# Async Crypter

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/miladiir/node-async-crypter-ts/Node.js%20CI)](https://github.com/Miladiir/node-async-crypter-ts/actions/workflows/node.js.yml?query=branch%3Amain) [![License](https://img.shields.io/npm/l/async-crypter)](https://github.com/Miladiir/node-async-crypter-ts/blob/main/LICENSE) [![NPM](https://img.shields.io/npm/v/async-crypter)](https://www.npmjs.com/package/async-crypter) [![Sponsors](https://img.shields.io/github/sponsors/Miladiir)](https://github.com/sponsors/Miladiir)

Easy, safe and powerful asynchronous AES-256-GCM encryption for NodeJS.

### Table of contents

- [Motivation](#motivation)
- [Usage](#usage)
- [Installation](#installation)
- [Updates](#updates)

### License & Support

This package is licensed under the Unlicense. Please consider supporting me and my projects by
becoming [a sponsor](https://github.com/sponsors/Miladiir).

## Motivation

I was trying to find out how to encrypt files and text using NodeJS. I managed to find my way through the API, but
implementing this was not trivial. I therefore decided to open source what I found out.

Other packages sometimes had implementation errors that can be actually dangerous in production (iv reuse), where
missing features (no aad), or lacked in code quality. One common thing I found while looking at other packages was, that
Buffers where stringified before encryption, which did not make much sense to me.

In the vast sea of packages, there is probably something just as good as this. But this is mine and I am happy with the
way it turned out. I hope you can enjoy and put it to good use as well.

## Usage

To encrypt some text, an image, some file or anything else you can store in a Buffer, first instantiate a new instance
of `Crypter`. At this point you should have a pretty strong password, that will be used to encrypt your data.

```typescript
import {Crypter} from "async-crypter";
// or import xyz from "async-crypter" if you want to use the default export.

const crypterOne = new Crypter("Super Secret Password");

const bufferedSecret = Buffer.from("Another Secret");
const crypterTwo = new Crypter(bufferedSecret);
```

Two instances of `Crypter` that were instantiated with the same secret will behave in the same way. You can now use your
instance to encrypt and decrypt buffers. Just make sure that you do not modify the encrypted buffer, otherwise you will
probably destroy the data stored in it. If you need to modify your data in a meaningful way, first decrypt and then
encrypt again. The encrypted buffer should only be stored or transmitted, but not modified.

Encryption and decryption use the secret, that is stored in the crypter instance.

```typescript
// Pseudocode
async () => {
    const someBuffer = Buffer.from(...);
    const encryptedData = await crypter.encrypt(someBuffer);
...
    const decryptedData = await crypter.decrypt(encryptedData);
}
```

You can also pass additional authenticated data (AAD) as the optional second parameter in both `encrypt` and `decrypt`.
AAD can be used as a second factor. If you loose either the secret or the AAD, the Buffer cannot be decrypted. AAD are
not that useful if they stay the same for all encryption operations and their usage depends on the use-case. I therefore
left them out of the class and you will have to pass them correctly. AAD are just another Buffer with information that
you perceive as a second important authentication factor for the purpose of encryption. AAD might be the users ID, or
the original path of the file, or a combination of multiple criteria. This is up to you to implement.

**Remember**: You will need the same secret, the full and unmodified encrypted Buffer and the same AAD to decrypt your
Buffer again.

## Properties

Buffers that are encrypted using this library can be decrypted using standard cryptograhpy libraries, e.g. openssl, and
the information about the encrypted Buffer layout.

- Data is encrypted using nodejs crypto apis linked to openssl and the aes-256-gcm cipher.
- The output buffer contains the salt (64 bytes), initalization vector (16 bytes), authentication tag (16 bytes) and of
  course the encrypted data (remaining bytes).

The actual encryption key is generated using `pbkdf2` with the original secret (stored in `Crypter` instance), a
randomly generated salt (the one that is later prepended to the encrypted Buffer), an iteration count of 100.000, a
keylength of 32 and `sha512` as the digest. In addition to this ever changing encryption key, additional safety is
provided by a changing initialization vector per encryption. Combined this ensures that every encryption is completely
non-predictable. Even if you use the same password and the same Buffer, you will generate distinct resulting encrypted
Buffers. As explained in [Usage](#usage), additional authenticated data can be used to further influence the encryption.
Unlike iv, salt and tag, the add are not included in the encrypted buffer. Think of aad more like a second password.

I unfortunately cannot find much information on how the authentication tag is formed. I must warn you that the
authentication tag is probably implementation specific to NodeJS and that you can probably only form or verify one using
the crypto APIs of node.

## Installation

`npm i --save async-crypter`

The [npm package](https://www.npmjs.com/package/async-crypter) contains the transpiled JavaScript code and TypeScript
typings. Both are generated from the TypeScript source code. You do not need TypeScript to use this package.

## Updates

**async-crypter** follows [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200). This means that you
can decide based on the version number of the package if manual update intervention is required. Head over
to [Github Releases](https://github.com/Miladiir/node-async-crypter-ts/releases) or check the CHANGELOG file for changes
between versions. In most cases *npm* will take care of updates for you automatically with `npm update` or an
alternative of your choice.

(Not recommended)
`npm i --save async-crypter@latest` will force the package to the latest version in any case.
