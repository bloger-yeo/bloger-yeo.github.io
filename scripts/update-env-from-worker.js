import { spawnSync } from "node:child_process";
import fs from "node:fs";

const res = spawnSync("wrangler", ["deploy"], { encoding: "utf-8" });
const output = res.stdout + res.stderr;
const m = output.match(/https:\/\/[a-zA-Z0-9.-]+\.workers\.dev/);
if (!m) { console.error("Worker URL not found.\n"+output); process.exit(1); }
const worker = m[0];

let env = fs.readFileSync(".env", "utf-8").split(/\r?\n/);
const setKV = (k,v)=>{
  let found=false;
  env = env.map(line=>{
    if (line.startsWith(k+"=")) { found=true; return `${k}="${v}"`; }
    return line;
  });
  if (!found) env.push(`${k}="${v}"`);
};
setKV("WORKER_ORIGIN", worker);
setKV("KAKAO_REDIRECT_URI", worker + "/oauth/callback");

fs.writeFileSync(".env", env.join("\n"));
console.log("Updated .env with WORKER_ORIGIN & KAKAO_REDIRECT_URI:", worker);
