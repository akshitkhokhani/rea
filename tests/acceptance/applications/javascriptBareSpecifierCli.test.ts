import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { expect } from "vitest";
import { z } from "zod";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const nativeResolutionsSchema = z.array(
  z.object({
    specifier: z.string(),
    path: z.string().nullable(),
    code: z.string().nullable(),
  }),
);

for (const kind of ["import", "require"] as const)
  cliTest(
    `preserves bare package identity and URL suffix controls for ${kind} through CLI and stdio MCP`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-bare-specifier-");
      const specifiers = [
        "fixture",
        "fixture?query",
        "fixture#fragment",
        "@scope/fixture",
        "@scope/fixture?query",
        "@scope/fixture#fragment",
        "punct#pkg",
        "@scope/punct#pkg",
        "./local.cjs?query",
        "./local.cjs#literal.cjs",
      ];
      const entry = kind === "import" ? "main.mjs" : "main.cjs";
      const source = specifiers
        .map((specifier, index) =>
          kind === "import"
            ? `import ${JSON.stringify(specifier)};`
            : `const value${index} = require(${JSON.stringify(specifier)});`,
        )
        .join("\n");
      await writeFixtureFiles(root, {
        [entry]: source,
        "local.cjs": 'module.exports = "local";',
        "local.cjs#literal.cjs": 'module.exports = "literal";',
        ...Object.fromEntries(
          [
            "fixture",
            "@scope/fixture",
            "punct",
            "punct#pkg",
            "@scope/punct",
            "@scope/punct#pkg",
          ].flatMap((name) => [
            [
              `node_modules/${name}/package.json`,
              JSON.stringify({ main: "index.cjs" }),
            ],
            [
              `node_modules/${name}/index.cjs`,
              'throw new Error("must not execute");',
            ],
          ]),
        ),
      });
      const expression =
        kind === "import"
          ? "import.meta.resolve(specifier)"
          : "require.resolve(specifier)";
      const native = await promisify(execFile)(
        process.execPath,
        [
          "--input-type",
          kind === "import" ? "module" : "commonjs",
          "--eval",
          `console.log(JSON.stringify(${JSON.stringify(specifiers)}.map(specifier => {
          try { return {specifier, path: ${expression}, code: null}; }
          catch(error) { return {specifier, path: null, code: error.code}; }
        })));`,
        ],
        { cwd: root, timeout: 5_000 },
      );
      const nativeResolutions = nativeResolutionsSchema.parse(
        JSON.parse(native.stdout),
      );
      const output = await cli.run({
        arguments: ["analyze-javascript-application", root, "--json"],
      });
      expect(output.exitCode).toBe(0);
      const cliEvidence = parseEvidence(output.json);
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [resolve("scripts/rea.mjs"), "mcp"],
        cwd: process.cwd(),
        env: { PATH: process.env.PATH ?? "", REA_LOG_LEVEL: "silent" },
        stderr: "pipe",
      });
      const client = new Client({
        name: "bare-specifier-parity",
        version: "1",
      });
      try {
        await client.connect(transport);
        const response = await client.callTool({
          name: "analyze_javascript_application",
          arguments: { input_path: root },
        });
        expect(response.isError).not.toBe(true);
        const mcpEvidence = parseEvidence(response.structuredContent);
        expect(mcpEvidence.evidence_id).toBe(cliEvidence.evidence_id);
        const analysis = javascriptApplicationAnalysisResultSchema.parse(
          cliEvidence.normalized_result,
        );
        expect(mcpEvidence.normalized_result).toEqual(analysis);
        const canonicalRoot = await realpath(root);
        for (const [index, nativeResolution] of nativeResolutions.entries()) {
          const expected =
            nativeResolution.path === null
              ? null
              : relative(
                  canonicalRoot,
                  kind === "import"
                    ? fileURLToPath(nativeResolution.path)
                    : nativeResolution.path,
                )
                  .split(sep)
                  .join("/");
          if (expected === null)
            expect(nativeResolution.code).toBe(
              kind === "import" ? "ERR_MODULE_NOT_FOUND" : "MODULE_NOT_FOUND",
            );
          const edges = analysis.graph.edges.filter(
            ({ properties }) =>
              properties.module_link_kind === kind &&
              properties.specifier === nativeResolution.specifier,
          );
          expect(edges.length, nativeResolution.specifier).toBeGreaterThan(0);
          for (const edge of edges) {
            expect(
              edge.properties.resolved_path,
              nativeResolution.specifier,
            ).toBe(expected);
            expect(edge.properties.resolution_status === "resolved").toBe(
              expected !== null,
            );
            expect(edge.evidence).toMatchObject({
              artifact: {
                available: true,
                sha256: createHash("sha256").update(source).digest("hex"),
              },
              location: {
                available: true,
                value: {
                  kind: "source-range",
                  source: entry,
                  start: { line: index + 1 },
                },
              },
            });
          }
        }
      } finally {
        try {
          await client.close();
        } finally {
          await transport.close();
        }
      }
    },
    20_000,
  );
