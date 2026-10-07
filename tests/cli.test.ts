import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli";

describe("cli main()", () => {
  let logs: string[] = [];
  let errors: string[] = [];
  let outWrite: string[] = [];
  let tmp: string;
  let configPath: string;

  beforeEach(() => {
    logs = [];
    errors = [];
    outWrite = [];
    vi.spyOn(console, "log").mockImplementation((msg?: unknown) => void logs.push(String(msg)));
    vi.spyOn(console, "error").mockImplementation((msg?: unknown) => void errors.push(String(msg)));
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      outWrite.push(String(chunk));
      return true;
    }) as never);
    tmp = mkdtempSync(join(tmpdir(), "codesentinel-cli-"));
    configPath = join(tmp, "codesentinel.json");
    writeFileSync(configPath, JSON.stringify({ ignore: [], failOn: "none" }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(tmp, { recursive: true, force: true });
  });

  it("prints help and exits 0", () => {
    expect(main(["--help"])).toBe(0);
    expect(logs.join("\n")).toContain("Usage:");
  });

  it("prints version", () => {
    expect(main(["--version"])).toBe(0);
    expect(logs.join("\n")).toMatch(/CodeSentinel \d+\.\d+\.\d+/);
  });

  it("errors when no path is provided", () => {
    expect(main([])).toBe(2);
    expect(errors.join("\n")).toContain("no path provided");
  });

  it("rejects an unknown option", () => {
    expect(main([".", "--bogus"])).toBe(2);
    expect(errors.join("\n")).toContain("Unknown option");
  });

  it("rejects an invalid severity", () => {
    expect(main(["tests/fixtures/safe", "--severity", "extreme"])).toBe(2);
    expect(errors.join("\n")).toContain("invalid --severity");
  });

  it("rejects an invalid fail-on", () => {
    expect(main(["tests/fixtures/safe", "--fail-on", "extreme"])).toBe(2);
    expect(errors.join("\n")).toContain("invalid --fail-on");
  });

  it("rejects a missing option value", () => {
    expect(main(["tests/fixtures/safe", "--format"])).toBe(2);
    expect(errors.join("\n")).toContain("requires a value");
  });

  it("errors on a non-existent path", () => {
    expect(main(["does/not/exist"])).toBe(2);
    expect(errors.join("\n")).toContain("does not exist");
  });

  it("returns 0 for a clean tree with no fail-on", () => {
    expect(main(["tests/fixtures/safe", "--config", configPath])).toBe(0);
  });

  it("returns 1 when findings meet fail-on", () => {
    expect(main(["tests/fixtures/vulnerable", "--severity", "low", "--fail-on", "high", "--config", configPath])).toBe(1);
  });

  it("emits valid JSON for --format json", () => {
    const code = main(["tests/fixtures/vulnerable", "--format", "json", "--config", configPath]);
    expect(code).toBe(0);
    const parsed = JSON.parse(outWrite.join("").trim());
    expect(parsed.tool).toBe("CodeSentinel");
  });
});
