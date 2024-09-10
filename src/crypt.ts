const { subtle } = crypto;

const HASH_ITERATIONS = {
  1: 1000,
  2: 14000,
  3: 585000,
};
const hash = "SHA-256";
const HEX_BITS = 4;
export const IV_BITS = 128; // 16 * 8
export const ENCRYPTION_ALGO = "AES-CBC";

export const HexEncoder = {
  parse(hexString: string): Uint8Array {
    if (hexString.length % 2 !== 0) throw "Invalid hexString";
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

  stringify(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  },
};

async function decrypt(encryptedMsg: string, hashedPassword: string) {
  const ivLength = IV_BITS / HEX_BITS;
  const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
  const encrypted = encryptedMsg.substring(ivLength);

  const key = await subtle.importKey(
    "raw",
    HexEncoder.parse(hashedPassword),
    ENCRYPTION_ALGO,
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await subtle.decrypt(
    { name: ENCRYPTION_ALGO, iv },
    key,
    HexEncoder.parse(encrypted)
  );

  return new TextDecoder().decode(new Uint8Array(decryptedBuffer));
}

async function pbkdf2(
  password: string,
  salt: string,
  iterations: number,
  hashAlgorithm: string
): Promise<string> {
  const key = await subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const keyBytes = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: hashAlgorithm,
      iterations,
      salt: new TextEncoder().encode(salt),
    },
    key,
    256
  );

  return HexEncoder.stringify(new Uint8Array(keyBytes));
}

async function hashPasswordRound(
  password: string,
  salt: string,
  iterations: number,
  hashAlgorithm: string = hash
): Promise<string> {
  return pbkdf2(password, salt, iterations, hashAlgorithm);
}

async function decode(
  signedMsg: string,
  hashedPassword: string,
  salt: string,
  backwardCompatibleAttempt = 0,
  originalPassword = ""
): Promise<{ success: boolean; decoded?: string; message?: string }> {
  const encryptedHMAC = signedMsg.substring(0, 64);
  const encryptedMsg = signedMsg.substring(64);
  const decryptedHMAC = await signMessage(hashedPassword, encryptedMsg);

  if (decryptedHMAC !== encryptedHMAC) {
    originalPassword ||= hashedPassword;

    if (backwardCompatibleAttempt === 0) {
      const updatedHashedPassword = await hashPasswordRound(
        originalPassword,
        salt,
        HASH_ITERATIONS[3]
      );
      return decode(
        signedMsg,
        updatedHashedPassword,
        salt,
        1,
        originalPassword
      );
    }

    if (backwardCompatibleAttempt === 1) {
      let updatedHashedPassword = await hashPasswordRound(
        originalPassword,
        salt,
        HASH_ITERATIONS[2]
      );
      updatedHashedPassword = await hashPasswordRound(
        updatedHashedPassword,
        salt,
        HASH_ITERATIONS[3]
      );
      return decode(
        signedMsg,
        updatedHashedPassword,
        salt,
        2,
        originalPassword
      );
    }

    return { success: false, message: "Signature mismatch" };
  }

  return {
    success: true,
    decoded: await decrypt(encryptedMsg, hashedPassword),
  };
}

async function decryptAndReplaceHtml(
  hashedPassword: string,
  encryptedMsg: string,
  salt: string
): Promise<boolean> {
  const result = await decode(encryptedMsg, hashedPassword, salt);
  if (!result.success) {
    return false;
  }

  try {
    const { render, html, setReuseElements } = await import(
      // @ts-ignore
      "https://cdn.jsdelivr.net/npm/hydro-js"
    );

    setReuseElements(false);
    const element = html({ raw: result.decoded });
    render(element.querySelector("html") || element, document.documentElement);
  } catch {
    document.write(result.decoded!);
    document.close();
  }

  return true;
}

async function handleDecryptionOfPageFromHash(
  hashedPassword: string,
  encryptedMsg: string,
  salt: string
): Promise<{ isSuccessful: boolean; hashedPassword: string }> {
  const isDecryptionSuccessful = await decryptAndReplaceHtml(
    hashedPassword,
    encryptedMsg,
    salt
  );

  return {
    isSuccessful: isDecryptionSuccessful,
    hashedPassword,
  };
}

export async function hashPassword(
  password: string,
  salt: string
): Promise<string> {
  let hashedPassword = await hashPasswordRound(
    password,
    salt,
    HASH_ITERATIONS[1],
    "SHA-1"
  );
  hashedPassword = await hashPasswordRound(
    hashedPassword,
    salt,
    HASH_ITERATIONS[2]
  );
  return hashPasswordRound(hashedPassword, salt, HASH_ITERATIONS[3]);
}

export async function signMessage(
  hashedPassword: string,
  message: string
): Promise<string> {
  const key = await subtle.importKey(
    "raw",
    HexEncoder.parse(hashedPassword),
    { name: "HMAC", hash },
    false,
    ["sign"]
  );

  const signature = await subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  return HexEncoder.stringify(new Uint8Array(signature));
}

export async function handleDecryptionOfPage(
  password: string,
  encryptedMsg: string,
  salt: string
): Promise<ReturnType<typeof handleDecryptionOfPageFromHash>> {
  const hashedPassword = await hashPassword(password, salt);
  return handleDecryptionOfPageFromHash(hashedPassword, encryptedMsg, salt);
}
