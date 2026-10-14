// The one Node API vite.config.ts uses (to read the git commit for the build version). Declared here
// rather than adding @types/node, which would also put Node globals in scope for the browser code.
declare module "node:child_process" {
  export function execFileSync(file: string, args: string[], options: { encoding: "utf8"; stdio: ["ignore", "pipe", "ignore"] }): string;
}
