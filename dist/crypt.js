const { subtle } = crypto;
const HEX_BITS = 4;
export const IV_BITS = 16 * 8;
export const ENCRYPTION_ALGO = "AES-CBC";
export const HexEncoder = {
    parse: function (hexString) {
        if (hexString.length % 2 !== 0)
            throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },
    stringify: function (bytes) {
        const hexBytes = [];
        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);
    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);
    const outBuffer = await subtle.decrypt({
        name: ENCRYPTION_ALGO,
        iv: iv,
    }, key, HexEncoder.parse(encrypted));
    return new TextDecoder().decode(new Uint8Array(outBuffer));
}
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const keyBytes = await subtle.deriveBits({
        name: "PBKDF2",
        hash: hashAlgorithm,
        iterations,
        salt: new TextEncoder().encode(salt),
    }, key, 256);
    return HexEncoder.stringify(new Uint8Array(keyBytes));
}
async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
    const encryptedHMAC = signedMsg.substring(0, 64);
    const encryptedMsg = signedMsg.substring(64);
    const decryptedHMAC = await signMessage(hashedPassword, encryptedMsg);
    if (decryptedHMAC !== encryptedHMAC) {
        originalPassword = originalPassword || hashedPassword;
        if (backwardCompatibleAttempt === 0) {
            const updatedHashedPassword = await hashThirdRound(originalPassword, salt);
            return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
        }
        if (backwardCompatibleAttempt === 1) {
            let updatedHashedPassword = await hashSecondRound(originalPassword, salt);
            updatedHashedPassword = await hashThirdRound(updatedHashedPassword, salt);
            return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
        }
        return { success: false, message: "Signature mismatch" };
    }
    return {
        success: true,
        decoded: await decrypt(encryptedMsg, hashedPassword),
    };
}
async function handleDecryptionOfPageFromHash(hashedPassword, encryptedMsg, salt) {
    const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword, encryptedMsg, salt);
    if (!isDecryptionSuccessful) {
        return {
            isSuccessful: false,
            hashedPassword,
        };
    }
    return {
        isSuccessful: true,
        hashedPassword,
    };
}
async function decryptAndReplaceHtml(hashedPassword, encryptedMsg, salt) {
    const result = await decode(encryptedMsg, hashedPassword, salt);
    if (!result.success) {
        return false;
    }
    document.write(result.decoded);
    document.close();
    return true;
}
export async function hashPassword(password, salt) {
    let hashedPassword = await hashLegacyRound(password, salt);
    hashedPassword = await hashSecondRound(hashedPassword, salt);
    return hashThirdRound(hashedPassword, salt);
}
export async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), {
        name: "HMAC",
        hash: "SHA-256",
    }, false, ["sign"]);
    const signature = await subtle.sign("HMAC", key, new TextEncoder().encode(message));
    return HexEncoder.stringify(new Uint8Array(signature));
}
export async function handleDecryptionOfPage(password, encryptedMsg, salt) {
    const hashedPassword = await hashPassword(password, salt);
    return handleDecryptionOfPageFromHash(hashedPassword, encryptedMsg, salt);
}
