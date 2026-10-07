import { execFile, spawn } from "child_process";

export function run(userInput) {
  execFile("ping", ["-c", "4", userInput]);
  spawn("cat", [userInput]);
}
