import { exec, execSync, spawn } from "child_process";

export function run(userInput) {
  exec(`ping -c 4 ${userInput}`);
  execSync("ls " + userInput);
  spawn(`cat ${process.argv[2]}`, { shell: true });
}
