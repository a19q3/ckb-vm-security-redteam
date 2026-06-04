---
name: ckb-vm-security-redteam
description: "Adversarial security testing for the CKB-VM RISC-V virtual machine. Covers instruction decoding, memory safety, ELF loading, syscall handling, atomic operations, snapshot consistency, and ASM interpreter divergence."
---

# CKB-VM Security Red Team

Use this skill when asked to test, audit, red-team, fuzz, or attack the CKB-VM (ckb-vm) RISC-V virtual machine for security vulnerabilities.

## Architecture Overview

ckb-vm is a RISC-V (RV64IMCB) virtual machine written in Rust, used to execute CKB scripts on-chain. It has two execution backends:

1. **Rust interpreter**: `src/machine/mod.rs` — pure Rust implementation, portable
2. **ASM backend**: `src/machine/asm/` — x86_64 JIT-compiled execution, performance-critical

Key components:

- **Decoder**: `src/decoder.rs` — instruction decoding with versioned ISA support
- **Instructions**: `src/instructions/` — per-instruction handlers (R-type, I-type, S-type, U-type, R4-type)
- **Register**: `src/instructions/register.rs` — Register trait with u32/u64 implementations
- **Memory**: `src/memory/` — Flat, Sparse, and WXorX (write-xor-execute) memory backends
- **Machine**: `src/machine/mod.rs` — CoreMachine, SupportMachine, DefaultMachine
- **ELF loader**: `src/elf.rs` — ELF parsing and program loading
- **Cost model**: `src/cost_model.rs` — cycle estimation
- **Snapshot**: `src/snapshot.rs`, `src/snapshot2.rs` — VM state serialization/resumption
- **Fuzz targets**: `fuzz/fuzz_targets/` — existing libfuzzer targets

## Attack Surface Map

### Surface 1: Instruction Decoding

**Target**: `src/decoder.rs` (889 lines)

The decoder is the first line of defense — malformed bytecode reaches every other component through it.

Test patterns:

1. **Invalid opcode handling**: What happens with reserved opcodes (especially in RV64 encoding space)? Does every opcode have a handler or a clean error path?
2. **Instruction length ambiguity**: RISC-V has 2-byte and 4-byte instructions. Can crafted 2-byte sequences that look like the start of a 4-byte instruction cause misalignment?
3. **Compressed instruction (RVC) abuse**: `src/instructions/rvc.rs` handles compressed instructions. Test boundary cases in 16-bit encoding space.
4. **Version-dependent decoding**: The decoder has `decode_bits()` with version parameter. Can version mismatches cause instruction reclassification?
5. **Decoder cache poisoning**: `reset_instructions_cache` exists — is the cache state consistent across snapshot/resume cycles?

### Surface 2: Memory Safety

**Target**: `src/memory/` — FlatMemory, SparseMemory, WXorXMemory

1. **WXorX bypass**: `WXorXMemory` enforces write-xor-execute. Test whether:
   - A page marked executable can be written to via a race in multi-threaded access
   - Memory pages can be re-flagged without clearing existing code
   - The flag check in `check_permission` covers all memory access paths
2. **Out-of-bounds access**: Test load/store at address boundaries:
   - Load 64-bit value at last byte of a page
   - Store across page boundaries with misaligned addresses
   - Address wrapping (0xFFFFFFFFFFFFFFFF + 1 → 0)
3. **Memory initialization gaps**: `SparseMemory` lazily allocates pages. Can uninitialized memory be read before explicit writes?
4. **LR/SC atomicity**: `load_reservation`/`store_conditional` — test whether:
   - LR can be set on addresses outside valid memory range
   - SC succeeds when no matching LR exists
   - LR reservation survives across context switches or snapshots
5. **FlatMemory overflow**: FlatMemory uses a contiguous buffer. Can very large load/store addresses cause integer overflow in offset calculations?

### Surface 3: ELF Loading

**Target**: `src/elf.rs` (211 lines)

This is a critical attack surface — on-chain scripts are loaded from ELF binaries.

1. **Malformed ELF headers**: Craft ELFs with:
   - Overlapping PT_LOAD segments
   - Extremely large p_memsz (much larger than p_filesz) — tests BSS/uninitialized memory handling
   - Zero p_memsz with non-zero p_filesz
   - Program headers pointing outside the ELF file
   - Very high p_vaddr values near u64::MAX
2. **Entry point manipulation**: Can the entry point be set outside any loaded segment? Can it point to an address that falls between segments?
3. **Bytes count overflow**: The parser checks `bytes.checked_add()` for total loaded bytes, but verify this handles wrapping correctly with adversarial segment sizes.
4. **goblin version differences**: Two goblin versions (v0.23 and v0.40) are used based on VM version. Test whether the same ELF parses differently between versions, producing divergent behavior.
5. **Flag conversion**: `convert_flags()` converts ELF p_flags to VM memory flags. Test whether invalid flag combinations (e.g., write+execute without read) are handled.

### Surface 4: Instruction Execution

**Target**: `src/instructions/execute.rs` (1636 lines)

1. **Arithmetic edge cases**: Test every arithmetic instruction with boundary values:
   - `SUB` with 0 - 0x8000_0000_0000_0000 (signed overflow)
   - `MUL` with u64::MAX * u64::MAX
   - `DIV` by zero
   - `REM` by zero and `i64::MIN % -1` (overflow trap in RISC-V spec)
   - `SRA` with shift amount >= 64
2. **Shift amount validation**: RISC-V specifies that shift amounts >= XLEN are masked. Verify all shift instructions (`SLL`, `SRL`, `SRA`, `SLLI`, `SRLI`, `SRAI`) properly mask the immediate.
3. **AMO (Atomic Memory Operations)**: Test all AMO instructions:
   - `LR.W`/`SC.W` and `LR.D`/`SC.D` — reservation semantics
   - `AMOSWAP`, `AMOADD`, `AMOXOR`, `AMOAND`, `AMOOR`, `AMOMIN`, `AMOMAX` — signed and unsigned variants
   - Misaligned AMO addresses
   - AMO on non-RW pages
4. **MOP extension**: Test M-class (multiplication/division) instructions for:
   - Division precision (integer division rounding)
   - Remainder sign correctness
   - High-product instructions (`MULH`, `MULHSU`, `MULHU`)
5. **A-extension**: Test atomic instructions with concurrent-style scenarios (even on single-threaded VM).
6. **ECALL/EBREAK handling**: Test that ecall properly invokes the registered syscall handler, and ebreak triggers the registered debugger.

### Surface 5: Register Operations

**Target**: `src/instructions/register.rs` (709 lines)

1. **Register x0 hardwiring**: RISC-V spec requires register x0 to always read as 0 and ignore writes. Test whether any instruction path can set x0 to non-zero.
2. **Sign extension correctness**: Test `sign_extend` and `zero_extend` for all width combinations (8/16/32/64 bit).
3. **Value overflow detection**: The `overflowing_*` methods must set overflow flags correctly. Verify on boundary values.
4. **Bit manipulation extensions**: Test `clz`, `ctz`, `cpop`, `clmul`, `clmulh`, `clmulr`, `orcb`, `rev8`, `rol`, `ror` with all-zero and all-one inputs.

### Surface 6: Machine Lifecycle

**Target**: `src/machine/mod.rs` (928 lines)

1. **Cycle counting**: Can cycle counting overflow? Can `add_cycles` be called in a way that bypasses `max_cycles` check?
2. **PC manipulation**: Test `update_pc` / `commit_pc` edge cases:
   - PC set to non-aligned address
   - PC set to 0 (null)
   - PC wrapping
3. **Reset signal**: Can `reset_signal` be abused to reinitialize the machine in an inconsistent state?
4. **Pause/Interrupt**: Test the pause mechanism — can a paused machine be resumed with corrupted state?

### Surface 7: Snapshot Consistency

**Target**: `src/snapshot.rs`, `src/snapshot2.rs`

Snapshots are used for VM context switching on CKB. Inconsistency = on-chain exploit.

1. **State completeness**: Does the snapshot capture ALL mutable machine state? Missing any register, flag, or memory page is a vulnerability.
2. **Resume correctness**: After snapshot → resume, is the machine in exactly the same state? Test with:
   - Programs at various PC positions
   - Active LR reservations
   - Partially written memory pages
   - WXorX flags set
3. **Snapshot2 vs Snapshot divergence**: There are two snapshot implementations. Test whether they produce equivalent results for the same program state.
4. **Page tracking**: `Snapshot2Context` tracks dirty pages. Can page tracking miss a write, causing stale data on resume?

### Surface 8: ASM vs Interpreter Divergence

**Target**: `src/machine/asm/` vs `src/machine/mod.rs`

This is the most dangerous surface — the ASM backend runs actual x86_64 machine code.

1. **Deterministic divergence**: The existing `fuzz/fuzz_targets/asm.rs` already tests ASM vs interpreter equivalence. But verify:
   - All instruction categories are covered
   - Flag states (carry, overflow) are equivalent
   - Memory access patterns are identical
2. **ASM unsafe blocks**: The ASM backend has ~20 `unsafe` blocks (see `src/machine/asm/mod.rs` and `src/machine/asm/traces.rs`). Key risks:
   - `MaybeUninit::zeroed().assume_init()` — is this truly safe for all field types?
   - Raw pointer arithmetic for memory/flags/frames
   - `Box::from_raw` — double-free risk if called twice
   - External C function calls via FFI
3. **Thread safety**: The ASM backend uses threading. Test whether shared state is properly synchronized.
4. **Signal handling**: `sa_sigaction` is used for pause. Test whether signal handlers interact correctly with the JIT code.

### Surface 9: Syscall Interface

**Target**: `ecall` handling in Machine trait implementations

1. **Syscall argument validation**: Are syscall arguments properly validated before being passed to the handler? Can a script pass arbitrary register values as syscall args?
2. **Syscall handler return value abuse**: Does the VM validate syscall return values? Can a malicious handler corrupt VM state through return values?
3. **Multiple ecall sequences**: Can rapid ecall sequences overflow the stack or corrupt memory?

### Surface 10: Fuzz Gap Analysis

The existing fuzz targets are in `fuzz/fuzz_targets/`:

| Target | Tests | Does NOT test |
|---|---|---|
| `interpreter.rs` | Determinism of interpreter | Correctness, edge cases, all ISAs |
| `asm.rs` | ASM vs interpreter equivalence | Snapshot paths, error paths |
| `isa_a.rs` | A-extension | Cross-instruction interactions |
| `isa_b.rs` | B-extension | Memory-backed B instructions |
| `isa_m.rs` | M-extension | Division edge cases |
| `snapshot.rs` | Snapshot1 resume | Multi-snapshot, nested snapshots |
| `snapshot2.rs` | Snapshot2 resume | Cross-version snapshots |

Missing fuzz targets to build:
- ELF loading fuzz (malformed ELFs)
- WXorX enforcement fuzz (write-then-execute sequences)
- Cycle overflow fuzz (programs designed to hit cycle limits exactly)
- Register x0 enforcement fuzz

## API Quick Reference (for writing adversarial tests)

These are the key APIs needed to construct adversarial test cases programmatically:

```rust
// Memory construction
let memory = WXorXMemory::new(1024 * 1024);  // size in bytes, must be non-zero

// Load code into memory (WXorX requires page-aligned addresses, i.e. multiples of 4096)
memory.init_pages(code_addr, code_size, FLAG_EXECUTABLE, Some(code_bytes), code_offset)
    .unwrap();

// Byte access
let val = memory.load8(&addr).unwrap();        // takes &u64, returns Result<u8>
let val = memory.load16(&addr).unwrap();       // returns Result<u16>
let val = memory.load64(&addr).unwrap();       // returns Result<u64>

// Store access
memory.store8(&addr, &value_u64).unwrap();     // value must be &u64 for all store* variants

// Machine builder
use ckb_vm::{
    machine::{DefaultMachineBuilder, RustCore},
    CoreMachine, DefaultCore, Memory,
};
let core = DefaultCore::<u64, WXorXMemory>::new(DefaultCore::max_cycles(), memory);
let mut machine = RustDefaultMachineBuilder::new(core)
    .instruction_cycle_func(Box::new(default_instruction_cycle_func))
    .build();

// Execution
use ckb_vm::decoder::InstDecoder;
let mut decoder = InstDecoder::new(ISA_IMC, ISA_B);
machine.step(&mut decoder).unwrap();          // needs &mut InstDecoder

// ELF loading
use ckb_vm::loader::parse_elf;
let metadata = parse_elf(&Bytes::from(elf_bytes), &mut memory).unwrap();

// Constants
const FLAG_EXECUTABLE: u8 = 2;
const FLAG_WRITABLE: u8 = 1;
```

## Execution Strategy

### Quick Wins Path (recommended for a single session)

Focus on the highest-yield attack surfaces that can be tested with minimal setup:

1. **Static analysis** — grep for `unsafe`, `unwrap()` in non-test code, `as u\d+` casts
2. **ELF entry point validation** — construct minimal ELF with out-of-range entry, verify parse_elf accepts it
3. **WXorX read-path gap** — load code, execute, then try reading executable pages via load8
4. **SC dirty flag** — trigger SC failure, check if FLAG_DIRTY is still set
5. **Arithmetic edge cases** — REM/DIV with i64::MIN and -1

### Full Audit Path

If multiple sessions are available:

#### Phase 1: Existing Fuzz Infrastructure
Check if fuzz targets compile and run.

#### Phase 2: Static Analysis
```bash
rg 'unsafe' src/ --type rust -n -c
rg 'unwrap\(\)|expect\(' src/ --type rust -g '!*tests*' -n
rg 'as u\d+|wrapping_|checked_|saturating_' src/ --type rust -n -c
rg 'boundary|bounds|overflow|out.of.bound' src/memory/ --type rust -n
rg 'check|validate|verify|guard|sanitize' src/elf.rs --type rust -n
```

#### Phase 3: Adversarial ELF Construction
Build minimal malformed ELFs targeting each ELF loading vulnerability.

#### Phase 4: Instruction-Level Adversarial Tests
Write assembly programs (as raw bytes) targeting:
1. All arithmetic boundary values
2. Misaligned memory access patterns
3. LR/SC without matching pairs
4. ECALL in tight loops (cycle exhaustion)
5. Self-modifying code attempts (should be blocked by WXorX)
6. Branch to address 0
7. JAL/JALR with extreme offsets

#### Phase 5: Snapshot Attack
1. Snapshot during active LR reservation → resume → attempt SC
2. Snapshot at various PC alignments → resume → verify execution
3. Multiple sequential snapshots → verify no state leakage

## Reporting Format

```
[FINDING] <title>
Severity: Critical / High / Medium / Low / Informational
Surface: Decoder / Memory / ELF / Instructions / Registers / Machine / Snapshot / ASM-Divergence / Syscall / Fuzz-Gap
Location: <file:line>
Attack vector: <how to trigger>
Impact: <what happens on-chain>
Evidence: <execution output or crash trace>
Recommendation: <fix>
```

## Critical Context

- **This is on-chain code.** Any bug in ckb-vm affects every CKB script execution. A single memory corruption or instruction misexecution could lead to fund loss.
- **Two backends must agree.** The ASM backend (x86_64) and Rust interpreter must produce identical results for every valid input. Any divergence is a critical finding.
- **WXorX is a security invariant.** Write-xor-execute prevents self-modifying code. Any bypass is a critical vulnerability.
- **Snapshot is a consensus component.** Snapshot/resume must be perfectly deterministic and complete. Missing state = consensus fork risk.
- **Do NOT modify the ckb-vm repo during red-teaming.** Write findings as reports only.
- **Do NOT file public issues.** Follow the security policy: encrypt and email to security@nervos.org.
