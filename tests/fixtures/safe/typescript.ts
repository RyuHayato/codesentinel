interface Env {
  [key: string]: string | undefined;
}

const env: Env = process.env as Env;

export function getSecret(key: string): string | undefined {
  return env[key];
}

export const hash = (input: string): string => {
  return "sha256:" + input;
};
