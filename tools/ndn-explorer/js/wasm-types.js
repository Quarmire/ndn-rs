// @ts-check
/**
 * ndn-wasm loader.
 *
 * Provides JSDoc typedefs for the WASM API and a best-effort async loader.
 * When `wasm-pack build crates/ndn-wasm --target web` has been run and the
 * output is present at `wasm/ndn_wasm.js`, the real WASM module is loaded.
 * Until then every exported value is null and callers fall back to pure-JS
 * simulation.
 *
 * Live ES-module export binding: importers that hold a reference to the
 * exported `wasmMod` variable will see the updated value once `initWasm()`
 * resolves, because ES module exports are live bindings.
 */

// ── Type definitions ──────────────────────────────────────────────────────────

/**
 * A parsed TLV node returned by `wasmMod.tlv_parse_hex()`.
 * Field names match the Rust serde default (snake_case).
 * @typedef {Object} WasmTlvNode
 * @property {number}        typ
 * @property {string}        type_name
 * @property {number}        length
 * @property {number}        start_byte
 * @property {number}        end_byte
 * @property {string}        value_hex   - space-separated lowercase hex of value bytes
 * @property {string|null}   value_text  - UTF-8 text if all bytes are printable ASCII
 * @property {WasmTlvNode[]} children
 */

/**
 * The full wasm-bindgen module object as imported from `wasm/ndn_wasm.js`.
 *
 * Free functions exposed by `#[wasm_bindgen]` in lib.rs:
 * @typedef {Object} WasmMod
 * @property {function(string, boolean, boolean, number, number): string} tlv_encode_interest
 *   Returns space-separated lowercase hex (e.g. "05 2b 07 ...").
 * @property {function(string, string, number): string} tlv_encode_data
 *   Returns space-separated lowercase hex.
 * @property {function(string): WasmTlvNode[]|{error:string}} tlv_parse_hex
 *   Parses hex (with or without spaces) into a TLV node tree.
 * @property {function(number): string} tlv_type_name
 *   Returns the human-readable name for a TLV type code.
 * @property {typeof import('./wasm-pipeline-class').WasmPipeline} WasmPipeline
 *   Single-node pipeline simulation class.
 * @property {typeof import('./wasm-topology-class').WasmTopology} WasmTopology
 *   Multi-node topology simulation class.
 * @property {function(any, string): any} load_topology_scenario
 *   Load a pre-built topology scenario into a WasmTopology instance.
 */

// ── Module export (live binding — updated by initWasm) ─────────────────────

/** @type {WasmMod|null} */
export let wasmMod = null;

// Legacy alias used by older call sites.
export { wasmMod as wasmPipeline };

// ── Loader ────────────────────────────────────────────────────────────────────

/**
 * Attempt to load the ndn-wasm WASM module.
 * Returns true on success, false if the module is not built yet.
 * Safe to call multiple times — subsequent calls are no-ops.
 * @returns {Promise<boolean>}
 */
export async function initWasm() {
  if (wasmMod !== null) return true;        // already loaded
  try {
    // Dynamic import — a missing file throws and is caught below.
    const mod = await import('../wasm/ndn_wasm.js');
    // wasm-pack --target web exports an async default init function.
    if (typeof mod.default === 'function') await mod.default();
    wasmMod = /** @type {WasmMod} */ (mod);
    console.info('[ndn-explorer] WASM module loaded — real Rust simulation active');
    return true;
  } catch {
    // Not built yet — pure-JS fallbacks remain active.
    return false;
  }
}

/**
 * Adapt a WASM TlvNode tree (snake_case field names) to the JS-native
 * TlvNode format used by the Packet Explorer's renderNode() function.
 *
 * @param {WasmTlvNode[]} wasmNodes
 * @returns {Array<{typ:number,typeName:string,length:number,startByte:number,endByte:number,valueHex:string,valueText:string|null,children:any[]}>}
 */
export function adaptWasmTlvTree(wasmNodes) {
  return wasmNodes.map(n => ({
    typ:       n.typ,
    typeName:  n.type_name,
    length:    n.length,
    startByte: n.start_byte,
    endByte:   n.end_byte,
    valueHex:  n.value_hex,
    valueText: n.value_text ?? null,
    children:  adaptWasmTlvTree(n.children ?? []),
  }));
}
