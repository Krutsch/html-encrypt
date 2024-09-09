#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { getRandomValues, subtle } from "node:crypto";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { minify } from "html-minifier-terser";
import { signMessage, hashPassword, HexEncoder, IV_BITS, ENCRYPTION_ALGO, } from "./crypt.js";
const removeHead = process.argv.includes("--removeHead");
const noMinify = process.argv.includes("--no-minify") || false;
async function encodeWithHashedPassword(msg, hashedPassword) {
    const encrypted = await encrypt(msg, hashedPassword);
    const hmac = await signMessage(hashedPassword, encrypted);
    return hmac + encrypted;
}
function generateRandomSalt() {
    const bytes = getRandomValues(new Uint8Array(128 / 8));
    return HexEncoder.stringify(new Uint8Array(bytes));
}
async function encrypt(msg, hashedPassword) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));
    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);
    const encrypted = await subtle.encrypt({
        name: ENCRYPTION_ALGO,
        iv: iv,
    }, key, new TextEncoder().encode(msg));
    return (HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted)));
}
function prompt(question) {
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    return new Promise((resolve) => {
        return rl.question(question, (answer) => {
            rl.close();
            return resolve(answer);
        });
    });
}
try {
    const path = process.argv.at(-1);
    if (!path?.endsWith(".html")) {
        console.error("Please specify a path to the .html file.");
        process.exit(1);
    }
    console.warn("This task will overwrite your specified .html file!");
    const salt = generateRandomSalt();
    const pw = await prompt("Enter your long, unusual password: ");
    const bodyPath = await prompt("Enter your optional path for your login template: ");
    const body = bodyPath
        ? await readFile(bodyPath, "utf-8")
        : `<script src="https://cdn.twind.style" crossorigin></script>
    <style>
      html {
        height: 100%;
      }
      body {
        display: block;
        height: 100%;
        width: 100%;
        background-color: rgb(17 24 39);
        color: rgb(241 245 249);
        font-size: 1rem;
        line-height: 1.5rem;
        overflow-x: hidden;
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
    </style>
      <main class="flex h-full place-content-center place-items-center">
      <div class="w-[37rem] rounded bg-slate-800 px-5 py-10 shadow-xl">
        <h1 class="mb-2 text-3xl font-bold">Passwort</h1>
        <form>
          <label class="grid"
            ><span class="text-slate-300 mb-1.5 mt-4"
              >Bitte gib das Passwort für diese Seite ein.</span
            >
            <input
              type="password"
              name="password"
              aria-label="Password"
              autocomplete="current-password"
              required
              autofocus
              class="appearance-none rounded border border-slate-400 bg-slate-900 px-3 py-2.5 focus-visible:border-teal-600 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-600"
            />
          </label>
          <button
            type="submit"
            class="mt-4 w-full rounded bg-slate-100 py-3 font-bold text-slate-800 !bg-slate-100"
          >
            Login
          </button>
        </form>
      </div>
    </main>`;
    let file = await readFile(path, "utf-8");
    const encryptedMsg = await encodeWithHashedPassword(file, await hashPassword(pw, salt));
    const cryptJS = await readFile(join(import.meta.dirname, "./crypt.js"), "utf-8");
    if (removeHead) {
        file = file.replace(/<head([^]*?)>[^]*?<\/head>/, "<head></head>");
    }
    file = file.replace(/<body([^]*?)>[^]*?<\/body>/, `<body$1><script type="module">
    const esm = ({raw}, ...vals) => URL.createObjectURL(new Blob([String.raw({raw}, ...vals)], {type: 'application/javascript'}));

    const { handleDecryptionOfPage } = await import("esmPLACEHOLDER");

    const $ = document.querySelector.bind(document);
    const encryptedMsg = "${encryptedMsg}";
    const salt = "${salt}";

    const main = $("main");
    $("form").addEventListener("submit", async function (e) {
      e.preventDefault();

      const password = $("input").value;
      const { isSuccessful } = await handleDecryptionOfPage(
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
</body>`);
    if (!noMinify) {
        file = await minify(file, {
            collapseWhitespace: true,
            removeComments: true,
            minifyJS: true,
            minifyCSS: true,
        });
        file = file.replace(/[\r\n]\s+/g, "");
    }
    file = file.replace('"esmPLACEHOLDER"', `esm\`${cryptJS}\``);
    await writeFile(path, file);
}
catch (err) {
    console.error(err);
}
