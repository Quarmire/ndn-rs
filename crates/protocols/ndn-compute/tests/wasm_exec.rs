//! WASM compute-executor witnesses (C-COMPUTE-05). Requires `--features wasm-exec`.
#![cfg(feature = "wasm-exec")]

use ndn_compute::{ComputeError, ComputeExecutor, WasmExecutor};

/// Echoes its input back as output via the `ndn_compute` host ABI.
const ECHO_WAT: &str = r#"
(module
  (import "ndn_compute" "input_len"    (func $input_len (result i32)))
  (import "ndn_compute" "read_input"   (func $read_input (param i32)))
  (import "ndn_compute" "write_output" (func $write_output (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "compute")
    (local $n i32)
    (local.set $n (call $input_len))
    (call $read_input (i32.const 0))
    (call $write_output (i32.const 0) (local.get $n))))
"#;

/// Spins forever — must trap on fuel exhaustion.
const SPIN_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "compute")
    (loop $l (br $l))))
"#;

#[test]
fn wasm_executor_echoes_input() {
    let wasm = wat::parse_str(ECHO_WAT).expect("assemble echo wat");
    let exec = WasmExecutor::from_bytes(&wasm, 1_000_000).expect("load echo module");

    let out = exec.execute(b"hello compute").expect("execute echo");
    assert_eq!(&out[..], b"hello compute");
}

#[test]
fn wasm_executor_traps_on_fuel_exhaustion() {
    let wasm = wat::parse_str(SPIN_WAT).expect("assemble spin wat");
    let exec = WasmExecutor::from_bytes(&wasm, 10_000).expect("load spin module");

    let err = exec
        .execute(b"")
        .expect_err("infinite loop must exhaust fuel");
    assert!(
        matches!(err, ComputeError::ComputeFailed(_)),
        "expected ComputeFailed, got {err:?}"
    );
}
