#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");

// ---------------------------------------------------------------------------
// Pipeline stage descriptions (hardcoded)
// ---------------------------------------------------------------------------
const PIPELINE_STAGES = {
  TlvDecode: {
    description:
      "Parses raw bytes into Interest/Data/Nack. Handles NDNLPv2 unwrapping and fragment reassembly.",
    position: "Stage 1 in both Interest and Data pipelines.",
    returns: "Continue(decoded), Drop(MalformedPacket/ScopeViolation)",
  },
  CsLookup: {
    description:
      "Checks Content Store for cached Data matching the Interest.",
    position: "Stage 2 in Interest pipeline.",
    returns: "Satisfy(cached data) on hit, Continue on miss",
  },
  PitCheck: {
    description:
      "Inserts Interest into PIT. Detects loops via nonce, aggregates duplicate Interests.",
    position: "Stage 3 in Interest pipeline.",
    returns: "Continue(new entry), Drop(LoopDetected/Suppressed)",
  },
  Strategy: {
    description:
      "Consults FIB and per-prefix strategy for forwarding decision.",
    position: "Stage 4 in Interest pipeline, stage 4 in Data pipeline.",
    returns: "Send(faces), Drop(NoRoute), Nack",
  },
  PitMatch: {
    description:
      "Matches incoming Data against PIT entries. Collects in-record faces for fan-out.",
    position: "Stage 2 in Data pipeline.",
    returns: "Continue(with out_faces), Drop(unsolicited)",
  },
  Validation: {
    description:
      "Optional signature verification via Validator + TrustSchema.",
    position: "Stage 3 in Data pipeline.",
    returns: "Satisfy(verified), Drop(InvalidSignature)",
  },
  CsInsert: {
    description: "Inserts verified Data into Content Store.",
    position: "Stage 5 in Data pipeline.",
    returns: "Satisfy(ctx)",
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loadCratesJson() {
  const jsonPath = path.join(PROJECT_ROOT, "tools/ndn-explorer/data/crates.json");
  try {
    const raw = await readFile(jsonPath, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function grepForType(typeName) {
  // Search for struct/enum/trait/type definitions
  const patterns = [
    `pub struct ${typeName}[< {(]`,
    `pub enum ${typeName}[< {]`,
    `pub trait ${typeName}[< {:]`,
    `pub type ${typeName}[< =]`,
  ];
  const combined = patterns.join("|");
  try {
    const { stdout } = await execFileAsync(
      "grep",
      ["-rn", "-E", combined, "--include=*.rs", PROJECT_ROOT],
      { maxBuffer: 1024 * 1024, timeout: 10000 }
    );
    return stdout.trim();
  } catch {
    return "";
  }
}

async function searchDocs(query) {
  const wikiDir = path.join(PROJECT_ROOT, "docs/wiki/src");
  try {
    const { stdout } = await execFileAsync(
      "grep",
      ["-rni", "--include=*.md", "-C", "2", query, wikiDir],
      { maxBuffer: 1024 * 1024, timeout: 10000 }
    );
    // Trim to a reasonable size
    const lines = stdout.split("\n");
    if (lines.length > 100) {
      return lines.slice(0, 100).join("\n") + `\n... (${lines.length - 100} more lines)`;
    }
    return stdout.trim() || "No results found.";
  } catch {
    return "No results found (wiki directory may not exist or query had no matches).";
  }
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "ndn-mcp",
  version: "0.1.0",
});

// -- lookup_crate -----------------------------------------------------------
server.tool(
  "lookup_crate",
  "Look up an ndn-rs workspace crate by name. Returns description, layer, key types, dependencies, and path.",
  { crate_name: z.string().describe("Crate name, e.g. 'ndn-packet' or 'ndn-fw'") },
  async ({ crate_name }) => {
    const data = await loadCratesJson();
    if (!data) {
      return {
        content: [
          {
            type: "text",
            text: "Could not load crates.json. Make sure tools/ndn-explorer/data/crates.json exists.",
          },
        ],
      };
    }
    const crate = data.crates.find(
      (c) => c.name === crate_name || c.name === `ndn-${crate_name}`
    );
    if (!crate) {
      const names = data.crates.map((c) => c.name).join(", ");
      return {
        content: [
          {
            type: "text",
            text: `Crate '${crate_name}' not found. Available crates: ${names}`,
          },
        ],
      };
    }
    const info = [
      `Crate: ${crate.name}`,
      `Description: ${crate.description}`,
      `Layer: ${crate.layer} (${crate.layer_num})`,
      `Path: ${crate.path}`,
      `Key types: ${(crate.key_types || []).join(", ")}`,
      `Workspace deps: ${(crate.workspace_deps || []).join(", ") || "(none)"}`,
    ];
    return { content: [{ type: "text", text: info.join("\n") }] };
  }
);

// -- lookup_type ------------------------------------------------------------
server.tool(
  "lookup_type",
  "Find the definition of a Rust type (struct, enum, trait, type alias) in the ndn-rs codebase.",
  { type_name: z.string().describe("Type name, e.g. 'Interest', 'Fib', 'LruCs'") },
  async ({ type_name }) => {
    const results = await grepForType(type_name);
    if (!results) {
      return {
        content: [
          {
            type: "text",
            text: `No definition found for '${type_name}'. Try a different name or check spelling.`,
          },
        ],
      };
    }
    // Format results relative to project root
    const formatted = results
      .split("\n")
      .map((line) => line.replace(PROJECT_ROOT + "/", ""))
      .join("\n");
    return { content: [{ type: "text", text: formatted }] };
  }
);

// -- spec_gaps --------------------------------------------------------------
server.tool(
  "spec_gaps",
  "Returns the contents of docs/spec-gaps.md listing known NDN spec gaps and deviations.",
  {},
  async () => {
    const filePath = path.join(PROJECT_ROOT, "docs/spec-gaps.md");
    try {
      const content = await readFile(filePath, "utf-8");
      return { content: [{ type: "text", text: content }] };
    } catch {
      return {
        content: [
          { type: "text", text: "docs/spec-gaps.md not found." },
        ],
      };
    }
  }
);

// -- pipeline_stage ---------------------------------------------------------
server.tool(
  "pipeline_stage",
  "Describe an NDN forwarding pipeline stage: what it does, its position, and possible Action returns.",
  {
    stage_name: z
      .string()
      .describe(
        "Stage name: TlvDecode, CsLookup, PitCheck, Strategy, PitMatch, Validation, CsInsert"
      ),
  },
  async ({ stage_name }) => {
    // Try exact match first, then case-insensitive
    let stage = PIPELINE_STAGES[stage_name];
    if (!stage) {
      const key = Object.keys(PIPELINE_STAGES).find(
        (k) => k.toLowerCase() === stage_name.toLowerCase()
      );
      stage = key ? PIPELINE_STAGES[key] : null;
    }
    if (!stage) {
      const available = Object.keys(PIPELINE_STAGES).join(", ");
      return {
        content: [
          {
            type: "text",
            text: `Unknown stage '${stage_name}'. Available stages: ${available}`,
          },
        ],
      };
    }
    const text = [
      `Stage: ${stage_name}`,
      `Description: ${stage.description}`,
      `Position: ${stage.position}`,
      `Returns: ${stage.returns}`,
    ].join("\n");
    return { content: [{ type: "text", text }] };
  }
);

// -- search_docs ------------------------------------------------------------
server.tool(
  "search_docs",
  "Search across all docs/wiki/src/**/*.md files for matching content. Returns relevant snippets.",
  { query: z.string().describe("Search query (case-insensitive grep pattern)") },
  async ({ query }) => {
    const results = await searchDocs(query);
    return { content: [{ type: "text", text: results }] };
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);
