import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyBaseline, loadBaseline, writeBaseline, findingKey } from "../src/baseline";
import { scan } from "../src/scanner/ruleEngine";
import { main } from "../src/cli";

describe("baseline", () => {
  it("round-trips findings through writeBaseline/loadBaseline/applyBaseline", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-baseline-"));
    try {
      const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "low" });
      const path = join(dir, "baseline.json");
      writeBaseline(path, result.findings);
      const onDisk = JSON.parse(readFileSync(path, "utf8"));
      expect(onDisk).toHaveLength(result.findings.length);

      const loaded = loadBaseline(path);
      const kept = applyBaseline(result.findings, loaded);
      expect(kept).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadBaseline tolerates a { findings: [...] } wrapper shape", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-baseline-"));
    try {
      const path = join(dir, "b.json");
      writeFileSync(path, JSON.stringify({ findings: [{ ruleId: "CS-001", filePath: "x.js", line: 1, column: 1 }] }));
      const set = loadBaseline(path);
      expect(set.has(findingKey({ ruleId: "CS-001", filePath: "x.js", line: 1, column: 1 }))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadBaseline returns empty for a missing file and throws for bad JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-baseline-"));
    try {
      expect(loadBaseline(join(dir, "nope.json")).size).toBe(0);
      const bad = join(dir, "bad.json");
      writeFileSync(bad, "not json");
      expect(() => loadBaseline(bad)).toThrow(/Invalid baseline/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("CLI --write-baseline + --baseline suppresses re-reported findings", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-baseline-"));
    try {
      const baselineFile = join(dir, "baseline.json");
      const config = join(dir, "cfg.json");
      writeFileSync(config, JSON.stringify({ ignore: [], failOn: "none" }));

      // Silence stdout
      const writeSpy = { called: 0 };
      const origWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = (() => {
        writeSpy.called++;
        return true;
      }) as never;
      try {
        const code1 = main(["tests/fixtures/vulnerable", "--config", config, "--write-baseline", baselineFile]);
        expect(code1).toBe(0);
        const code2 = main(["tests/fixtures/vulnerable", "--config", config, "--baseline", baselineFile, "--fail-on", "low"]);
        expect(code2).toBe(0); // everything suppressed -> threshold not hit
      } finally {
        process.stdout.write = origWrite;
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
