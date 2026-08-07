#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { getRandomValues, subtle } from "node:crypto";
import { join } from "node:path";
import { minify } from "html-minifier-terser";
import * as esbuild from "esbuild";
import {
  signMessage,
  hashPassword,
  HexEncoder,
  IV_BITS,
  ENCRYPTION_ALGO,
} from "./crypt.js";
import { prompt } from "./prompt.js";

const removeHead = process.argv.includes("--remove-head");
const noMinify = process.argv.includes("--no-minify") || false;
const ownTemplate = process.argv.includes("--own-template") || false;
const setPasswordOnCLI = process.argv.findIndex((arg) => arg === "-p");

async function encodeWithHashedPassword(
  msg: string,
  hashedPassword: string,
): Promise<string> {
  const encrypted = await encrypt(msg, hashedPassword);
  const hmac = await signMessage(hashedPassword, encrypted);
  return hmac + encrypted;
}

function generateRandomSalt(): string {
  const bytes = getRandomValues(new Uint8Array(16)); // 128 bits = 16 bytes
  return HexEncoder.stringify(bytes);
}

async function encrypt(msg: string, hashedPassword: string): Promise<string> {
  const iv = getRandomValues(new Uint8Array(IV_BITS / 8));

  const key = await subtle.importKey(
    "raw",
    HexEncoder.parse(hashedPassword),
    ENCRYPTION_ALGO,
    false,
    ["encrypt"],
  );

  const encrypted = await subtle.encrypt(
    { name: ENCRYPTION_ALGO, iv },
    key,
    new TextEncoder().encode(msg),
  );

  return (
    HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted))
  );
}

try {
  const filePath = process.argv.find(
    (arg) => arg.endsWith(".html") || arg.endsWith(".htm"),
  );

  if (!filePath) {
    console.error("Please specify a valid .html or .htm file.");
    process.exit(1);
  }

  console.warn("This operation will overwrite your specified .html file!");

  const salt = generateRandomSalt();

  const password =
    setPasswordOnCLI === -1
      ? await prompt("Enter your long, unusual password: ", true)
      : process.argv.at(setPasswordOnCLI + 1)!;
  const bodyPath = ownTemplate
    ? await prompt("Enter your optional path for your login template: ")
    : "";

  const body = ownTemplate
    ? await readFile(bodyPath, "utf-8")
    : getDefaultBodyTemplate();

  let htmlContent = await readFile(filePath, "utf-8");
  const encryptedMessage = await encodeWithHashedPassword(
    htmlContent,
    await hashPassword(password, salt),
  );

  let cryptJS = await readFile(
    join(import.meta.dirname, "./crypt.js"),
    "utf-8",
  );

  if (removeHead) {
    htmlContent = htmlContent.replace(
      /<head([^]*?)>[^]*?<\/head>/,
      '<head><meta name="viewport" content="width=device-width,initial-scale=1"></head>',
    );
  }

  htmlContent = htmlContent.replace(
    /<body([^]*?)>[^]*?<\/body>/,
    `<body$1>
      <script type="module">
        const esm = ({ raw }, ...vals) =>
          URL.createObjectURL(
            new Blob([String.raw({ raw }, ...vals)], {
              type: "application/javascript",
            }),
          );
        const { handleDecryptionOfPage } = await import("esmPLACEHOLDER");

        const encryptedMsg = "${encryptedMessage}";
        const salt = "${salt}";
        const main = document.querySelector("main");

        document.querySelector("form").addEventListener("submit", async (e) => {
          e.preventDefault();
          const password = document.querySelector("input").value;
          const isSuccessful = await handleDecryptionOfPage(
            password,
            encryptedMsg,
            salt
          );
          if (!isSuccessful) {
            main?.classList.remove("shake");
            main?.offsetWidth;
            main?.classList.add("shake");
          }
        });
      </script>
      ${body}
      <link
        rel="preload"
        href="https://cdn.jsdelivr.net/npm/hydro-js"
        as="script"
        crossorigin
      />
    </body>`,
  );

  if (!noMinify) {
    htmlContent = await minify(htmlContent, {
      collapseWhitespace: true,
      removeComments: true,
      minifyJS: true,
      minifyCSS: true,
    });
    htmlContent = htmlContent.replace(/[\r\n]\s+/g, "");
    cryptJS = (await esbuild.transform(cryptJS, { minify: true })).code;
  }

  htmlContent = htmlContent.replace('"esmPLACEHOLDER"', `esm\`${cryptJS}\``);
  await writeFile(filePath, htmlContent);
} catch (error) {
  console.error("An error occurred:", error);
}

function getDefaultBodyTemplate(): string {
  return `<style>
  *,
  ::before,
  ::after {
    box-sizing: border-box;
    border-width: 0;
    border-style: solid;
    border-color: #e5e7eb;
  }
  html {
    height: 100%;
    line-height: 1.5;
    overflow: hidden;
  }
  body {
    margin: 0;
    display: block;
    height: 100%;
    width: 100%;
    background-color: rgb(17 24 39) !important;
    color: rgb(241 245 249);
    font-size: 1rem;
    line-height: 1.5rem;
    overflow-x: hidden;
  }
  h1 {
    margin: 0;
    font-size: inherit;
    font-weight: inherit;
  }
  button,
  input {
    margin: 0;
    padding: 0;
    color: inherit;
    font: inherit;
    font-feature-settings: inherit;
    font-variation-settings: inherit;
    letter-spacing: inherit;
    line-height: inherit;
  }
  button {
    text-transform: none;
  }
  @keyframes shake {
    0% {
      transform: translateX(0);
    }
    6.5% {
      transform: translateX(-6px) rotateY(-9deg);
    }
    18.5% {
      transform: translateX(5px) rotateY(7deg);
    }
    31.5% {
      transform: translateX(-3px) rotateY(-5deg);
    }
    43.5% {
      transform: translateX(2px) rotateY(3deg);
    }
    50% {
      transform: translateX(0);
    }
  }
  .shake {
    animation: shake 2s;
  }
  .html-encrypt-login {
    display: flex;
    width: 100%;
    height: 100%;
    place-content: center;
    place-items: center;
  }
  .html-encrypt-card {
    box-sizing: border-box;
    width: 100%;
    max-width: 37rem;
    border-radius: 0.25rem;
    background: #1e293b;
    padding: 2.5rem 1.25rem;
    box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1),
      0 8px 10px -6px rgb(0 0 0 / 0.1);
  }
  .html-encrypt-title {
    margin: 0 0 0.5rem;
    font-size: 1.875rem;
    line-height: 2.25rem;
    font-weight: 700;
    text-align: center;
  }
  .html-encrypt-label {
    display: grid;
  }
  .html-encrypt-label-text {
    margin-top: 1rem;
    margin-bottom: 0.375rem;
    color: #cbd5e1;
  }
  .html-encrypt-input {
    box-sizing: border-box;
    width: 100%;
    appearance: none;
    border: 1px solid #94a3b8;
    border-radius: 0.25rem;
    background: #0f172a;
    padding: 0.625rem 0.75rem;
    color: inherit;
  }
  .html-encrypt-input:focus-visible {
    border-color: #0d9488;
    outline: 2px solid transparent;
    box-shadow: 0 0 0 1px #0891b2;
  }
  .html-encrypt-button {
    width: 100%;
    margin-top: 1rem;
    border: 0;
    border-radius: 0.25rem;
    background: #f1f5f9;
    padding: 0.75rem 0;
    color: #1e293b;
    font-weight: 700;
    cursor: pointer;
  }
  .html-encrypt-button:focus-visible {
    outline: 2px solid #22d3ee;
    outline-offset: 2px;
  }
  @media screen and (-webkit-min-device-pixel-ratio: 0) {
    input[type="password"],
    input[type="text"] {
      font-size: 16px;
    }
  }
</style>
<script type="module">
  document.querySelector("input").addEventListener("change", () => {
    if (document.body.querySelector("input:autofill")) {
      document.body.querySelector("button").click();
    }
  });
</script>
<main class="html-encrypt-login">
  <div class="html-encrypt-card">
    <h1 class="html-encrypt-title">Passwort</h1>
    <form>
      <label class="html-encrypt-label"
        ><span class="html-encrypt-label-text"
          >Bitte gib das Passwort für diese Seite ein.</span
        >
        <input
          type="password"
          name="password"
          aria-label="Password"
          autocomplete="current-password"
          required
          autofocus
          class="html-encrypt-input"
        />
      </label>
      <button
        type="submit"
        class="html-encrypt-button"
      >
        Login
      </button>
    </form>
  </div>
</main>`;
}
