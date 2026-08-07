import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { prompt } from "../dist/prompt.js";

const CLI = resolve("dist/encrypt.js");
const PASSWORD = "a-long-test-password";

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
  });
}

async function withTempDirectory(callback) {
  const directory = await mkdtemp(join(tmpdir(), "html-encrypt-test-"));

  try {
    return await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function getEncryptedData(html) {
  const encryptedMessage = html.match(
    /const\s+encryptedMsg\s*=\s*"([0-9a-f]+)"/,
  )?.[1];
  const salt = html.match(/const\s+salt\s*=\s*"([0-9a-f]+)"/)?.[1];

  assert.ok(encryptedMessage, "generated page contains encrypted message");
  assert.ok(salt, "generated page contains salt");

  return { encryptedMessage, salt };
}

test("encrypts .htm files and generated page decrypts with correct password", async () => {
  await withTempDirectory(async (directory) => {
    const filePath = join(directory, "private.htm");
    const plaintext =
      '<!doctype html><html><head><style>body{background:#123}</style></head><body data-theme="night"><p>private content</p></body></html>';
    await writeFile(filePath, plaintext);

    const result = runCli([filePath, "-p", PASSWORD, "--no-minify"]);

    assert.equal(result.status, 0, result.stderr);
    const encryptedPage = await readFile(filePath, "utf8");
    assert.doesNotMatch(encryptedPage, /private content/);
    assert.match(encryptedPage, /body\{background:#123\}/);
    assert.match(encryptedPage, /data-theme="night"/);
    assert.doesNotMatch(encryptedPage, /cdn\.twind\.style/);
    assert.match(
      encryptedPage,
      /@media screen and \(-webkit-min-device-pixel-ratio: 0\)/,
    );
    assert.match(encryptedPage, /font-size: 16px/);

    const { encryptedMessage, salt } = getEncryptedData(encryptedPage);
    if (!globalThis.crypto) {
      globalThis.crypto = webcrypto;
    }

    const { handleDecryptionOfPage } = await import("../dist/crypt.js");
    const originalDocument = globalThis.document;
    let decryptedPage = "";
    globalThis.document = {
      close() {},
      write(value) {
        decryptedPage = value;
      },
    };

    try {
      assert.equal(
        await handleDecryptionOfPage(PASSWORD, encryptedMessage, salt),
        true,
      );
      assert.equal(decryptedPage, plaintext);
    } finally {
      if (originalDocument === undefined) {
        delete globalThis.document;
      } else {
        globalThis.document = originalDocument;
      }
    }
  });
});

test("masks interactive password prompt input", async () => {
  class FakeInput extends EventEmitter {
    isTTY = true;
    rawModes = [];

    setRawMode(mode) {
      this.rawModes.push(mode);
    }

    resume() {}

    pause() {}
  }

  const input = new FakeInput();
  const output = {
    chunks: [],
    write(chunk) {
      this.chunks.push(String(chunk));
      return true;
    },
  };

  const answerPromise = prompt("Password: ", true, input, output);
  input.emit("data", "s3cr");
  input.emit("data", "\u007f3t\n");

  assert.equal(await answerPromise, "s3c3t");
  assert.deepEqual(input.rawModes, [true, false]);
  assert.equal(output.chunks.join(""), "Password: \n");
});

test("rejects an incorrect password without rendering plaintext", async () => {
  await withTempDirectory(async (directory) => {
    const filePath = join(directory, "private.html");
    await writeFile(
      filePath,
      "<!doctype html><html><body><p>private content</p></body></html>",
    );

    const result = runCli([filePath, "-p", PASSWORD, "--no-minify"]);
    assert.equal(result.status, 0, result.stderr);

    const { encryptedMessage, salt } = getEncryptedData(
      await readFile(filePath, "utf8"),
    );
    if (!globalThis.crypto) {
      globalThis.crypto = webcrypto;
    }

    const { handleDecryptionOfPage } = await import("../dist/crypt.js");
    const originalDocument = globalThis.document;
    let rendered = false;
    globalThis.document = {
      close() {},
      write() {
        rendered = true;
      },
    };

    try {
      assert.equal(
        await handleDecryptionOfPage("wrong-password", encryptedMessage, salt),
        false,
      );
      assert.equal(rendered, false);
    } finally {
      if (originalDocument === undefined) {
        delete globalThis.document;
      } else {
        globalThis.document = originalDocument;
      }
    }
  });
});

test("rejects tampered ciphertext without rendering plaintext", async () => {
  await withTempDirectory(async (directory) => {
    const filePath = join(directory, "private.html");
    await writeFile(
      filePath,
      "<!doctype html><html><body><p>private content</p></body></html>",
    );

    const result = runCli([filePath, "-p", PASSWORD, "--no-minify"]);
    assert.equal(result.status, 0, result.stderr);

    const { encryptedMessage, salt } = getEncryptedData(
      await readFile(filePath, "utf8"),
    );
    const tamperedMessage = `${encryptedMessage.slice(0, -1)}${
      encryptedMessage.endsWith("0") ? "1" : "0"
    }`;
    if (!globalThis.crypto) {
      globalThis.crypto = webcrypto;
    }

    const { handleDecryptionOfPage } = await import("../dist/crypt.js");
    const originalDocument = globalThis.document;
    let rendered = false;
    globalThis.document = {
      close() {},
      write() {
        rendered = true;
      },
    };

    try {
      assert.equal(
        await handleDecryptionOfPage(PASSWORD, tamperedMessage, salt),
        false,
      );
      assert.equal(rendered, false);
    } finally {
      if (originalDocument === undefined) {
        delete globalThis.document;
      } else {
        globalThis.document = originalDocument;
      }
    }
  });
});

test("rejects unsupported input extensions", async () => {
  await withTempDirectory(async (directory) => {
    const filePath = join(directory, "private.txt");
    await writeFile(filePath, "private content");

    const result = runCli([filePath, "-p", PASSWORD]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /\.html or \.htm/);
  });
});
