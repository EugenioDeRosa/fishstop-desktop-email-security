import { spawn } from "node:child_process";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

function run(args) {
  return spawn(npmCommand, args, {
    stdio: "inherit",
    shell: false,
  });
}

if (process.platform === "win32") {
  const build = run(["run", "build"]);
  const exitCode = await new Promise((resolve) => build.once("exit", resolve));
  if (exitCode !== 0) process.exit(exitCode ?? 1);
}

const server = process.platform === "win32"
  ? run(["exec", "vite", "preview", "--", "--host", "127.0.0.1", "--port", "1420", "--strictPort"])
  : run(["run", "dev"]);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => server.kill(signal));
}

server.once("exit", (code) => process.exit(code ?? 0));
