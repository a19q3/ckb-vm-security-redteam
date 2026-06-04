---
name: ckb-vm-security-redteam
description: "Adversarial security testing for the CKB-VM RISC-V virtual machine. Covers decoder, memory, ELF loading, syscalls, atomics, snapshots, and ASM/interpreter divergence."
---

# CKB-VM Security Red Team

Use this skill when asked to audit, red-team, fuzz, or attack the CKB-VM (`ckb-vm`) RISC-V virtual machine for security vulnerabilities.

Work from the target repository root supplied by the user. Do not hard-code local paths in commands, reports, or the skill metadata. If no repository path is supplied, locate it first and then refer to it as "the ckb-vm checkout" in public artefacts.

## Ground Rules

- Treat the target `ckb-vm` checkout as read-only during red-team work unless the user explicitly asks for fixes.
- Put findings in a report. Do not silently patch the VM while auditing.
- Do not file public issues for security-sensitive findings. Follow the upstream security policy.
- Keep evidence concrete: command output, harness output, file/line locations, or reproducible test cases.
- Before publishing a skill or report, strip user names, absolute local paths, temporary paths, and environment-specific details.

## Architecture Map

`ckb-vm` is a Rust RISC-V VM used to execute CKB scripts on-chain. The main security-sensitive components are:

- Decoder: `src/decoder.rs`
- Instruction handlers: `src/instructions/`, especially `src/instructions/execute.rs`
- Register trait and arithmetic helpers: `src/instructions/register.rs`
- Memory backends: `src/memory/flat.rs`, `src/memory/sparse.rs`, `src/memory/wxorx.rs`
- Machine lifecycle and cycle accounting: `src/machine/mod.rs`
- ASM backend: `src/machine/asm/`
- ELF loader: `src/elf.rs`
- Snapshots: `src/snapshot.rs`, `src/snapshot2.rs`
- Fuzz targets: `fuzz/fuzz_targets/`

The highest-risk invariant classes are:

- ASM backend and Rust interpreter must agree.
- WXorX must prevent writes to executable pages.
- ELF loader metadata must not admit malformed executable state.
- Snapshot/resume must preserve all consensus-relevant mutable state.
- Cycle counting must fail deterministically on overflow or max-cycle breach.

## Attack Surface Checklist

### Decoder

- Reserved and malformed opcodes must fail cleanly.
- RVC 16-bit instruction boundaries must not desynchronise later 32-bit decoding.
- Version-dependent decoding must not reclassify an instruction unsafely.
- Decoder instruction cache reset must stay consistent across reset/snapshot paths.

### Memory

- WXorX write paths must check `FLAG_WRITABLE`/`FLAG_EXECUTABLE` consistently.
- Cross-page loads/stores must reject out-of-bounds and wrapping addresses.
- Uninitialised sparse pages should read deterministically and not leak stale data.
- LR/SC should preserve the architectural reservation semantics and avoid dirtying pages on failed SC.
- `FlatMemory` and `SparseMemory` intentionally do not enforce WXorX by themselves; normal script execution should wrap them in `WXorXMemory`.
- Do not report a SparseMemory u16 page-index truncation bug: this was a false positive. SparseMemory has a `Vec<u16>` index table for page slots, but the practical risk must be demonstrated against current allocation bounds; do not assume truncation from the field type alone.

### ELF Loader

Focus here first; it produces fast, high-value findings.

- Entry point outside all loaded executable segments.
- `p_filesz > p_memsz`.
- `p_memsz == 0 && p_filesz > 0`.
- `p_vaddr + p_memsz` and page-rounding overflow.
- Segment source range outside the ELF file.
- Overlapping `PT_LOAD` segments with conflicting flags.
- W+X flags and unreadable segments.
- Divergent behaviour between goblin versions used for VM versions.

### Instructions

- Division by zero and RISC-V defined edge cases.
- Shift masking for `SLL`, `SRL`, `SRA`, immediate forms, and word forms.
- AMO and LR/SC misalignment, permissions, reservation clearing, and snapshot persistence.
- Bit-manipulation operations on all-zero, all-one, sign-bit, and alternating-bit inputs.
- `ECALL`/`EBREAK` control flow and cycle accounting.

Important correction: RISC-V signed `DIV/REM` overflow (`INT_MIN / -1`, `INT_MIN % -1`) is defined behaviour, not a trap. Do not report "missing trap" as a vulnerability.

### Registers

- x0 must remain zero through every write path.
- Sign/zero extension must match RV32/RV64 semantics.
- Register arithmetic wrappers must be checked for backend divergence, not ordinary Rust overflow expectations.

### Machine Lifecycle

- `add_cycles` must reject overflow and max-cycle excess.
- PC updates must handle misaligned, zero, out-of-range, and wrapping values deterministically.
- `reset_signal` must only reset decoder cache state intended by the VM.
- Pause/resume must not corrupt PC, cycles, memory flags, or LR reservation.

### Snapshots

- Snapshot and Snapshot2 should capture registers, PC, cycles, max cycles, dirty pages, flags, and `load_reservation_address`.
- Test active LR reservation across snapshot/resume, but note that current snapshot formats do include `load_reservation_address`.
- Dirty page tracking should not miss writes through raw machine memory APIs.
- Snapshot2 page-source tracking must not restore stale data after mixed cached-source and raw writes.

### ASM Backend

- Run ASM-enabled tests when the platform supports it: `cargo test --features detect-asm`.
- Inspect unsafe blocks in `src/machine/asm/mod.rs` and `src/machine/asm/traces.rs`.
- Treat interpreter/ASM divergence as critical unless a version-gated compatibility rule explains it.

## API Quick Reference

The following signatures match the current `ckb-vm` public API used in adversarial harnesses. Keep this section close when writing tests.

```rust
use ckb_vm::{
    CoreMachine, DefaultCoreMachine, ISA_A, ISA_IMC, Memory, RustDefaultMachineBuilder,
    SparseMemory, SupportMachine, WXorXMemory,
    elf::{LoadingAction, ProgramMetadata},
    machine::VERSION2,
    memory::{FLAG_EXECUTABLE, FLAG_FREEZED, FLAG_WRITABLE},
};
use ckb_vm::bytes::Bytes;
use ckb_vm::decoder::{DefaultDecoder, InstDecoder};
```

### Machine Builder

```rust
let isa = ISA_IMC | ISA_A;
let memory_size: usize = 1024 * 1024; // must be 4096-aligned
let max_cycles = u64::MAX;

let core = DefaultCoreMachine::<u64, WXorXMemory<SparseMemory<u64>>>::new_with_memory(
    isa,
    VERSION2,
    max_cycles,
    memory_size,
);

let mut machine = RustDefaultMachineBuilder::new(core)
    .instruction_cycle_func(Box::new(ckb_vm::cost_model::constant_cycles))
    .build();
```

Notes:

- `new_with_memory(..., memory_size)` takes `usize`, not `u64`.
- Memory size must be page-aligned; `SparseMemory::new` and `FlatMemory::new` panic on non-aligned sizes.
- Use `WXorXMemory<SparseMemory<u64>>` for permission-sensitive tests. Bare `SparseMemory` is useful only when intentionally bypassing WXorX.

### Raw Bytecode Loading

Use `load_program_with_metadata` to bypass ELF parsing.

```rust
let code = Bytes::from(vec![0x93, 0x00, 0x00, 0x00]); // ADDI x1, x0, 0
let addr = 0x10000u64;

let metadata = ProgramMetadata {
    actions: vec![LoadingAction {
        addr,
        size: 4096,
        flags: FLAG_EXECUTABLE | FLAG_FREEZED,
        source: 0..code.len() as u64,
        offset_from_addr: 0,
    }],
    entry: addr,
};

machine
    .load_program_with_metadata(&code, &metadata, std::iter::empty())
    .expect("load failed");
```

Notes:

- `LoadingAction::source` is a `Range<u64>`, not a segment id.
- `offset_from_addr` is required.
- WXorX `init_pages` requires page-aligned `addr` and page-rounded `size`.
- `load_program_with_metadata` takes `&ProgramMetadata`, not `Option<ProgramMetadata>`.

### Stepping

```rust
let mut decoder = DefaultDecoder::new::<u64>(isa, VERSION2);
let result = machine.step(&mut decoder);
```

Notes:

- `DefaultDecoder::new` comes from the `InstDecoder` trait; import `ckb_vm::decoder::InstDecoder`.
- `step` requires a mutable decoder reference.

### Memory Reads And Stores

```rust
let addr = 0x10000u64;
let value = 42u64;

machine.memory_mut().store8(&addr, &value).unwrap();
machine.memory_mut().store16(&addr, &value).unwrap();
machine.memory_mut().store32(&addr, &value).unwrap();
machine.memory_mut().store64(&addr, &value).unwrap();

let loaded8: u64 = machine.memory_mut().load8(&addr).unwrap();
let loaded64: u64 = machine.memory_mut().load64(&addr).unwrap();
let bytes = machine.memory_mut().load_bytes(addr, 16).unwrap();
```

Notes:

- `store8/16/32/64` take `&addr` and `&value`.
- `load8/16/32/64` take `&addr` and return the register type (`u64` in this scaffold).
- `load_bytes(addr, size)` uses plain `u64` arguments and returns `Bytes`.

### ELF Parser Harness

For malformed ELF tests, prefer a tiny external harness crate that depends on the local checkout:

```toml
[dependencies]
ckb-vm = { path = "../ckb-vm" }
```

Then generate byte vectors and call:

```rust
use ckb_vm::bytes::Bytes;
use ckb_vm::elf::parse_elf;
use ckb_vm::machine::VERSION2;

let elf = Bytes::from(elf_bytes);
let metadata = parse_elf::<u64>(&elf, VERSION2);
```

This avoids modifying the ckb-vm repository while still giving compile-checked evidence.

## Minimal Adversarial Test Scaffold

Use this as the starting point for instruction or raw-bytecode probes:

```rust
use ckb_vm::{
    CoreMachine, DefaultCoreMachine, ISA_IMC, Memory, RustDefaultMachineBuilder,
    SparseMemory, SupportMachine, WXorXMemory,
    bytes::Bytes,
    decoder::{DefaultDecoder, InstDecoder},
    elf::{LoadingAction, ProgramMetadata},
    machine::VERSION2,
    memory::{FLAG_EXECUTABLE, FLAG_FREEZED},
};

fn build_machine() -> ckb_vm::DefaultMachine<
    DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>,
> {
    let core = DefaultCoreMachine::<u64, WXorXMemory<SparseMemory<u64>>>::new_with_memory(
        ISA_IMC,
        VERSION2,
        u64::MAX,
        1024 * 1024,
    );

    RustDefaultMachineBuilder::new(core)
        .instruction_cycle_func(Box::new(ckb_vm::cost_model::constant_cycles))
        .build()
}

#[test]
fn adversarial_raw_bytecode_case() {
    let mut machine = build_machine();
    let code = Bytes::from(vec![0x93, 0x00, 0x00, 0x00]);
    let addr = 0x10000u64;
    let metadata = ProgramMetadata {
        actions: vec![LoadingAction {
            addr,
            size: 4096,
            flags: FLAG_EXECUTABLE | FLAG_FREEZED,
            source: 0..code.len() as u64,
            offset_from_addr: 0,
        }],
        entry: addr,
    };

    machine
        .load_program_with_metadata(&code, &metadata, std::iter::empty())
        .unwrap();

    let mut decoder = DefaultDecoder::new::<u64>(ISA_IMC, VERSION2);
    let result = machine.step(&mut decoder);
    assert!(result.is_ok(), "{result:?}");
}
```

## One-Session Workflow

A real session usually cannot complete a full audit. Use this order for practical progress:

1. Establish baseline:

```bash
cargo test
cargo test --features detect-asm
```

2. Run static probes:

```bash
rg 'unsafe' src --type rust -n -c
rg 'unwrap\(\)|expect\(' src --type rust -g '!*tests*' -n
rg 'as u\d+|wrapping_|checked_|saturating_' src --type rust -n -c
rg 'check|validate|verify|guard|sanitize|entry|p_memsz|p_filesz|p_vaddr' src/elf.rs -n
```

3. Quick wins:

- ELF: build malformed ELF cases for entry outside segments, `p_filesz > p_memsz`, zero `p_memsz`, overflowed `p_memsz`, overlapping segments, and W+X flags.
- AMO/LR/SC: failed SC should not dirty memory; LR reservation should survive snapshot/resume.
- WXorX: write-to-executable must fail; ordinary read-from-executable is not a WXorX violation unless the project claims read secrecy.
- Snapshot: run existing `resume` and `resume2` tests with ASM enabled.

4. Write findings immediately. Do not leave verified evidence as chat-only notes.

## Full Audit Workflow

Use this only when the user asks for a longer audit.

1. Baseline tests and ASM-enabled tests.
2. Static analysis of unsafe, unwrap/expect, integer casts, wrapping arithmetic, and ELF validation.
3. Malformed ELF harness.
4. Raw-bytecode instruction probes.
5. Snapshot and ASM/interpreter differential testing.
6. Fuzzing if `cargo-fuzz` is available.

Fuzz commands, when available:

```bash
cd fuzz
cargo fuzz run interpreter -- -max_total_time=60
cargo fuzz run asm -- -max_total_time=60
```

## Reporting Template

Write findings in this format:

```text
[FINDING] <title>
Severity: Critical / High / Medium / Low / Informational
Surface: Decoder / Memory / ELF / Instructions / Registers / Machine / Snapshot / ASM-Divergence / Syscall / Fuzz-Gap
Location: <file:line>
Attack vector: <how to trigger>
Impact: <what happens on-chain or to deterministic execution>
Evidence: <command output, harness output, or crash trace>
Recommendation: <fix or mitigation>
Status: Verified / Not verified / False positive
```

At the end of each pass, include:

- Repository branch and commit, without absolute local path.
- Commands run and whether they passed.
- Harnesses used, with temporary/local paths redacted if the report will be published.
- Verified non-issues and removed false positives.
- Follow-up tests that were not run, and why.

## Reference Files

- `references/verified-findings.md`: latest verified findings and false-positive corrections.
- `references/test-patterns.md`: focused compile-ready snippets for adversarial tests.
