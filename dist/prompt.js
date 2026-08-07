import { createInterface } from "node:readline";
export function prompt(question, masked = false, input = process.stdin, output = process.stdout) {
    if (masked && input.isTTY && input.setRawMode) {
        output.write(question);
        input.setRawMode(true);
        input.resume();
        return new Promise((resolve, reject) => {
            let answer = "";
            const cleanup = () => {
                input.off("data", onData);
                input.setRawMode?.(false);
                input.pause();
            };
            const onData = (chunk) => {
                for (const character of chunk.toString()) {
                    if (character === "\u0003") {
                        cleanup();
                        output.write("\n");
                        reject(new Error("Input cancelled"));
                        return;
                    }
                    if (character === "\r" || character === "\n") {
                        cleanup();
                        output.write("\n");
                        resolve(answer);
                        return;
                    }
                    if (character === "\u007f" || character === "\b") {
                        answer = [...answer].slice(0, -1).join("");
                        continue;
                    }
                    if (character >= " ") {
                        answer += character;
                    }
                }
            };
            input.on("data", onData);
        });
    }
    const rl = createInterface({ input, output });
    return new Promise((resolve) => rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
    }));
}
