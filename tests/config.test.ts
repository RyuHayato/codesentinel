import { describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, DEFAULT_CONFIG } from "../src/config";

function withConfig(contents: string | null): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "codesentinel-test-"));
  if (contents !== null) writeFileSync(join(dir, ".codesentinelrc.json"), contents, "utf8");
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("loadConfig", () => {
  it("returns defaults when no config file exists", () => {
    const { dir, cleanup } = withConfig(null);
    try {
      const cfg = loadConfig(dir);
      expect(cfg).toEqual(DEFAULT_CONFIG);
    } finally {
      cleanup();
    }
  });

  it("merges custom ignore paths with defaults", () => {
    const { dir, cleanup } = withConfig(JSON.stringify({ ignore: ["vendor", "docs"] }));
    try {
      const cfg = loadConfig(dir);
      expect(cfg.ignore).toContain("node_modules");
      expect(cfg.ignore).toContain("vendor");
      expect(cfg.ignore).toContain("docs");
    } finally {
      cleanup();
    }
  });

  it("applies severity overrides and rule toggles", () => {
    const { dir, cleanup } = withConfig(JSON.stringify({ rules: { "CS-006": "off", "CS-008": "high" } }));
    try {
      const cfg = loadConfig(dir);
      expect(cfg.rules["CS-006"]).toBe("off");
      expect(cfg.rules["CS-008"]).toBe("high");
    } finally {
      cleanup();
    }
  });

  it("throws on invalid JSON", () => {
    const { dir, cleanup } = withConfig("{ not json");
    try {
      expect(() => loadConfig(dir)).toThrow(/Invalid JSON/);
    } finally {
      cleanup();
    }
  });

  it("throws on invalid rule setting", () => {
    const { dir, cleanup } = withConfig(JSON.stringify({ rules: { "CS-001": "banana" } }));
    try {
      expect(() => loadConfig(dir)).toThrow(/Invalid value for rule/);
    } finally {
      cleanup();
    }
  });

  it("falls back to default severity for garbage values", () => {
    const { dir, cleanup } = withConfig(JSON.stringify({ severity: "extreme" }));
    try {
      expect(loadConfig(dir).severity).toBe(DEFAULT_CONFIG.severity);
    } finally {
      cleanup();
    }
  });

  it("respects failOn and format", () => {
    const { dir, cleanup } = withConfig(JSON.stringify({ failOn: "high", format: "sarif" }));
    try {
      const cfg = loadConfig(dir);
      expect(cfg.failOn).toBe("high");
      expect(cfg.format).toBe("sarif");
    } finally {
      cleanup();
    }
  });
});
