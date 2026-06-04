# CKB-VM Verified Findings (2026-06-04)

Scope: live red-team pass against a `ckb-vm` checkout on branch `develop`, commit `d1a1cfc`.

Method:

- `cargo test` passed.
- `cargo test --features detect-asm` passed, including ASM, resume, resume2, and ASM/interpreter regression tests.
- An external harness generated malformed ELF64/RISC-V inputs and called `parse_elf`, `load_elf`, memory reads, and one execution step without modifying the `ckb-vm` checkout.

## HIGH

### [FINDING] ELF loader executes bytes beyond `p_memsz` when `p_filesz > p_memsz`

Severity: High
Surface: ELF
Location: `src/elf.rs:181-203`, `src/memory/mod.rs:86-105`
Attack vector: Submit an ELF with a `PT_LOAD` segment where `p_filesz` is larger than `p_memsz`, and mark the segment readable and executable (`PF_R | PF_X`).
Impact: ckb-vm accepts a malformed ELF and materialises the full file slice into an executable page even though the ELF segment declares a smaller memory extent. In the harness, `p_memsz = 1`, `p_filesz = 16`, `entry = 0x10000` loaded successfully; the first 16 bytes were present at `0x10000`, and the first instruction executed successfully.
Evidence:

```text
exec_filesz_gt_memsz: parse=Ok(... size: 4096, source: 256..272 ...)
exec_filesz_gt_memsz: load=Ok(16); pc=0x10000
exec_filesz_gt_memsz: mem[0x10000..+16]=Ok(b"\x01\x02...\x10")
exec_filesz_gt_memsz: first_step=Ok(()); pc_after=0x10002
```

Recommendation: Reject `PT_LOAD` segments where `p_filesz > p_memsz` before constructing `LoadingAction`. Use checked arithmetic for `p_vaddr + p_memsz`, `p_vaddr + p_filesz`, and page rounding. Add an ELF-loader regression test with executable `p_filesz > p_memsz`.

## MEDIUM

### [FINDING] ELF entry point is not validated against loaded executable segments

Severity: Medium
Surface: ELF
Location: `src/elf.rs:135-209`, `src/machine/mod.rs:140-170`
Attack vector: Submit an ELF whose `e_entry` points outside all `PT_LOAD` ranges, for example `entry = 0xDEAD0000` while the only segment is loaded at `0x10000`.
Impact: Loading succeeds and commits PC to an address that was never loaded. Execution then fails at runtime with an out-of-bounds or permission error. This is deterministic, but it lets malformed scripts pass the loader boundary and defer failure into execution.
Evidence:

```text
entry_outside_load: parse=Ok(... entry: 3735879680)
entry_outside_load: load=Ok(4); pc=0xdead0000
entry_outside_load: first_step=Err(MemOutOfBound(3735879680, Memory))
```

Recommendation: During ELF parsing, require `e_entry` to fall within a loaded `PT_LOAD` range, preferably one whose converted VM flags include `FLAG_EXECUTABLE`.

### [FINDING] ELF segment size arithmetic can wrap to zero

Severity: Medium
Surface: ELF
Location: `src/elf.rs:183-185`, `src/bits.rs:1-6`
Attack vector: Submit a `PT_LOAD` segment with extremely large `p_memsz`, such as `u64::MAX`.
Impact: `p_memsz.wrapping_add(padding_start)` and `round_page_up` can wrap the VM loading size to `0`. The malformed segment then loads successfully, counts file bytes as loaded, and leaves the committed entry point on an uninitialised/non-executable page. This is a loader validation failure and can mask oversized memory declarations.
Evidence:

```text
wrapped_memsz: parse=Ok(... size: 0, source: 256..257 ...)
wrapped_memsz: load=Ok(1); pc=0x10000
wrapped_memsz: first_step=Err(MemWriteOnExecutablePage(16))
```

Recommendation: Replace wrapping arithmetic in ELF segment extent calculation with checked arithmetic. Reject any rounded segment size that overflows, shrinks below `p_memsz + padding_start`, or becomes zero while the segment has non-zero file or memory size.

### [FINDING] Zero-memory `PT_LOAD` segments with non-zero file data are accepted

Severity: Medium
Surface: ELF
Location: `src/elf.rs:181-203`, `src/machine/mod.rs:140-170`
Attack vector: Submit a `PT_LOAD` segment with `p_memsz = 0` and `p_filesz > 0`.
Impact: `parse_elf` returns a `LoadingAction` with `size = 0` but a non-empty source range. `load_elf` returns `Ok(bytes)` and commits PC even though no page was initialised for the segment. This is another malformed ELF accepted at load time and failed only at execution.
Evidence:

```text
zero_memsz_nonzero_filesz: parse=Ok(... size: 0, source: 256..272 ...)
zero_memsz_nonzero_filesz: load=Ok(16); pc=0x10000
zero_memsz_nonzero_filesz: mem[0x10000..+16]=Ok(b"\0"...)
zero_memsz_nonzero_filesz: first_step=Err(MemWriteOnExecutablePage(16))
```

Recommendation: Reject `p_memsz == 0 && p_filesz > 0`. More generally, reject any `PT_LOAD` where the declared memory range cannot contain the declared file range.

## LOW

### [FINDING] Failed SC still performs a same-value store and marks the page dirty

Severity: Low
Surface: Instructions / Snapshot
Location: `src/instructions/execute.rs:257-268`, `src/instructions/execute.rs:388-399`
Attack vector: Execute `SC.W` or `SC.D` without a matching active LR reservation.
Impact: On failure, the handler loads the current memory value and stores it back. The architectural memory value is unchanged and `rd` is set to failure (`1`), but memory backends mark the page dirty because a store occurred. This can enlarge snapshots and complicate dirty-page reasoning; it is not currently a consensus divergence in the tested suite.
Evidence: Static inspection shows failed `SC` takes the current memory value from `load32/load64`, then unconditionally calls `store32/store64`. Existing SC and snapshot tests pass in interpreter and ASM-enabled test runs.
Recommendation: On failed SC, set `rd = 1`, clear LR, and return without writing memory. Add a regression asserting that failed SC does not set `FLAG_DIRTY`.

### [FINDING] Memory constructors panic on non-page-aligned sizes

Severity: Low
Surface: Memory
Location: `src/memory/sparse.rs:73`, `src/memory/flat.rs:35`
Attack vector: Instantiate `SparseMemory::new` or `FlatMemory::new` with a size that is not a multiple of the RISC-V page size.
Impact: The API panics via `assert!`. This is not reachable through normal validated script execution, but it is brittle for embedders and fuzz harnesses.
Evidence: Existing unit tests confirm the invariant; constructors enforce it by panic rather than `Result`.
Recommendation: Expose fallible constructors for embedder-controlled memory sizes, or document the panic contract explicitly.

## Verified Non-Issues / Removed False Positives

- W+X ELF segments are rejected.
- WXorX write-to-executable checks are enforced for normal stores and AMO write paths.
- WXorX does not block ordinary data reads from executable pages. This is not a WXorX violation: the invariant is write-xor-execute, not read-xor-execute.
- Bare `SparseMemory` and `FlatMemory` do not enforce WXorX by design. The public `run` helper wraps the chosen memory backend in `WXorXMemory`.
- RISC-V `DIV/REM` signed overflow is not a trap condition. The earlier report that `i64::MIN / -1` or `% -1` must trap was incorrect and has been removed.
- Snapshot and Snapshot2 both serialise `load_reservation_address`; active LR reservation state is not omitted in this revision.
- `cargo-fuzz` was not installed in the tested environment, so no libFuzzer run was performed during this pass.
