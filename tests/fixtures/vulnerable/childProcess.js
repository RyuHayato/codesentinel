import { execSync } from "child_process";
import { spawn } from "child_process";

export function build(userInput) {
  execSync("make " + userInput);
  spawn("bash", ["-c", "echo hi"], { shell: true });
}
