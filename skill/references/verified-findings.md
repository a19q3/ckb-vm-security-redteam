# CKB-VM Verified Findings (2026-06-04)

Scope: live red-team pass and follow-up re-verification against `ckb-vm` branch `develop`, commit `d1a1cfc`.

Method:

- `cargo test` passed.
- `cargo test --features detect-asm` passed, including ASM, resume, resume2, and ASM/interpreter regression tests.
- An external harness generated malformed ELF64/RISC-V inputs and called current `parse_elf`, `load_elf`, memory reads, one interpreter `step`, failed `SC.W`, and memory constructors without modifying the target checkout.
- Re-verification confirmed every reported H/M/L finding on the current checkout.

## HIGH

### [FINDING] ELF loader executes bytes beyond `p_memsz` when `p_filesz > p_memsz`

Severity: High
Status: Re-verified
Surface: ELF
Location: `src/elf.rs:181-203`, `src/memory/mod.rs:86-105`, `src/machine/mod.rs:146-164`

Attack vector: submit an ELF with an executable `PT_LOAD` segment where `p_filesz` is larger than `p_memsz`.

Impact: ckb-vm accepts a malformed ELF and materialises the full file slice into an executable page even though the ELF segment declares a smaller memory extent. In the harness, `p_memsz = 1`, `p_filesz = 16`, and `entry = 0x10000` loaded successfully; the first 16 bytes were present at `0x10000`, and the first instruction executed successfully.

Evidence:

```text
h1_filesz_gt_memsz: parse=Ok(ProgramMetadata { actions: [LoadingAction { addr: 65536, size: 4096, flags: 3, source: 256..272, offset_from_addr: 0 }], entry: 65536 })
h1_filesz_gt_memsz: load=Ok(16); pc=0x10000
h1_filesz_gt_memsz: mem16=Ok(b"\x01\x02\x13\0\0\0\x13\0\0\0\x13\0\0\0\x13\0")
h1_filesz_gt_memsz: step=Ok(()); pc_after=0x10002
```

Recommendation: reject `PT_LOAD` segments where `p_filesz > p_memsz` before constructing `LoadingAction`. Use checked arithmetic for segment extents and page rounding. Add an ELF-loader regression test with executable `p_filesz > p_memsz`.

## MEDIUM

### [FINDING] ELF entry point is not validated against loaded executable segments

Severity: Medium
Status: Re-verified
Surface: ELF
Location: `src/elf.rs:135-209`, `src/machine/mod.rs:117-173`

Attack vector: submit an ELF whose `e_entry` points outside all `PT_LOAD` ranges, for example `entry = 0xDEAD0000` while the only segment is loaded at `0x10000`.

Impact: loading succeeds and commits PC to an address that was never loaded. Execution then fails at runtime with an out-of-bounds or permission error. This is deterministic, but it lets malformed scripts pass the loader boundary and defer failure into execution.

Evidence:

```text
m1_entry_outside_load: parse=Ok(ProgramMetadata { actions: [LoadingAction { addr: 65536, size: 4096, flags: 3, source: 256..260, offset_from_addr: 0 }], entry: 3735879680 })
m1_entry_outside_load: load=Ok(4); pc=0xdead0000
m1_entry_outside_load: step=Err(MemOutOfBound(3735879680, Memory)); pc_after=0xdead0000
```

Recommendation: during ELF parsing, require `e_entry` to fall within a loaded `PT_LOAD` range, preferably one whose converted VM flags include `FLAG_EXECUTABLE`.

### [FINDING] ELF segment size arithmetic can wrap to zero

Severity: Medium
Status: Re-verified
Surface: ELF
Location: `src/elf.rs:183-185`, `src/bits.rs:1-6`

Attack vector: submit a `PT_LOAD` segment with extremely large `p_memsz`, such as `u64::MAX`.

Impact: `p_memsz.wrapping_add(padding_start)` and `round_page_up` can wrap the VM loading size to `0`. The malformed segment then loads successfully, counts file bytes as loaded, and leaves the committed entry point on an uninitialised/non-executable page. This masks malformed oversized memory declarations.

Evidence:

```text
m2_wrapped_memsz: parse=Ok(ProgramMetadata { actions: [LoadingAction { addr: 65536, size: 0, flags: 3, source: 256..257, offset_from_addr: 0 }], entry: 65536 })
m2_wrapped_memsz: load=Ok(1); pc=0x10000
m2_wrapped_memsz: step=Err(MemWriteOnExecutablePage(16)); pc_after=0x10000
```

Recommendation: replace wrapping arithmetic in ELF segment extent calculation with checked arithmetic. Reject any rounded segment size that overflows, shrinks below `p_memsz + padding_start`, or becomes zero while the segment has non-zero file or memory size.

### [FINDING] Zero-memory `PT_LOAD` segments with non-zero file data are accepted

Severity: Medium
Status: Re-verified
Surface: ELF
Location: `src/elf.rs:181-203`, `src/machine/mod.rs:146-164`

Attack vector: submit a `PT_LOAD` segment with `p_memsz = 0` and `p_filesz > 0`.

Impact: `parse_elf` returns a `LoadingAction` with `size = 0` but a non-empty source range. `load_elf` returns `Ok(bytes)` and commits PC even though no page was initialised for the segment.

Evidence:

```text
m3_zero_memsz_nonzero_filesz: parse=Ok(ProgramMetadata { actions: [LoadingAction { addr: 65536, size: 0, flags: 3, source: 256..272, offset_from_addr: 0 }], entry: 65536 })
m3_zero_memsz_nonzero_filesz: load=Ok(16); pc=0x10000
m3_zero_memsz_nonzero_filesz: step=Err(MemWriteOnExecutablePage(16)); pc_after=0x10000
```

Recommendation: reject `p_memsz == 0 && p_filesz > 0`. More generally, reject any `PT_LOAD` where the declared memory range cannot contain the declared file range.

## LOW

### [FINDING] Failed SC still performs a same-value store and marks the page dirty

Severity: Low
Status: Re-verified
Surface: Instructions / Snapshot
Location: `src/instructions/execute.rs:257-268`, `src/instructions/execute.rs:388-399`, `src/memory/sparse.rs:169-181`, `src/memory/flat.rs:188-199`

Attack vector: execute `SC.W` or `SC.D` without a matching active LR reservation.

Impact: on failure, the handler loads the current memory value and stores it back. The architectural memory value is unchanged and `rd` is set to failure (`1`), but memory backends mark the page dirty because a store occurred. This can enlarge snapshots and complicate dirty-page reasoning; it is not currently a consensus divergence.

Evidence:

```text
failed_sc_dirty: load=Ok(8); before=Ok(0); before_bytes=Ok(b"\xaa\xbb\xcc\xdd"); step=Ok(()); rd=x3=0x1; after=Ok(4); after_bytes=Ok(b"\xaa\xbb\xcc\xdd")
```

`after=Ok(4)` is `FLAG_DIRTY`.

Recommendation: on failed SC, set `rd = 1`, clear LR, and return without writing memory. Add a regression asserting failed `SC.W` and `SC.D` do not set `FLAG_DIRTY`.

### [FINDING] Memory constructors panic on non-page-aligned sizes

Severity: Low
Status: Re-verified
Surface: Memory API
Location: `src/memory/sparse.rs:75`, `src/memory/flat.rs:37`

Attack vector: instantiate `SparseMemory::new` or `FlatMemory::new` with a size that is not a multiple of the RISC-V page size.

Impact: the API panics via `assert!`. This is not reachable through normal validated script execution, but it is brittle for embedders and fuzz harnesses.

Evidence:

```text
constructor_panics: sparse_panicked=true; flat_panicked=true
```

Recommendation: expose fallible constructors for embedder-controlled memory sizes, or document the panic contract explicitly.

## Verified Non-Issues / Removed False Positives

- W+X ELF segments are rejected.
- WXorX write-to-executable checks are enforced for normal stores and AMO write paths.
- WXorX does not block ordinary data reads from executable pages. This is not a WXorX violation: the invariant is write-xor-execute, not read-xor-execute.
- Bare `SparseMemory` and `FlatMemory` do not enforce WXorX by design. The public `run` helper wraps the chosen memory backend in `WXorXMemory`.
- RISC-V `DIV/REM` signed overflow is not a trap condition.
- Snapshot and Snapshot2 both serialise `load_reservation_address`; active LR reservation state is not omitted in this revision.
- `cargo-fuzz` was not installed in the tested environment, so no libFuzzer run was performed during this pass.

## Fix Priority

1. H1: enforce `p_filesz <= p_memsz`.
2. M2 and M3: replace wrapping segment arithmetic with checked validation and reject zero-sized malformed segments.
3. M1: validate `e_entry` against loaded executable ranges.
4. L1: avoid dirtying pages on failed SC.
5. L2: add fallible memory constructors or document the panic contract.
