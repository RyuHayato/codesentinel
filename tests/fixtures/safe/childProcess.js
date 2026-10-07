import { execFile, spawn } from "child_process";

export function build(target) {
  execFile("make", [target]);
  spawn("echo", ["hi"]);
}
