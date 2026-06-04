# CKB-VM Adversarial Test Patterns

These snippets are intended to compile against the current `ckb-vm` public API. Use them as starting points for temporary harnesses or focused tests.

## Imports

```rust
use ckb_vm::{
    CoreMachine, DefaultCoreMachine, ISA_A, ISA_IMC, Memory, RustDefaultMachineBuilder,
    SparseMemory, SupportMachine, WXorXMemory,
    bytes::Bytes,
    decoder::{DefaultDecoder, InstDecoder},
    elf::{LoadingAction, ProgramMetadata},
    machine::VERSION2,
    memory::{FLAG_EXECUTABLE, FLAG_FREEZED},
};
```

## Machine Builder

```rust
fn build_machine() -> ckb_vm::DefaultMachine<
    DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>,
> {
    let core = DefaultCoreMachine::<u64, WXorXMemory<SparseMemory<u64>>>::new_with_memory(
        ISA_IMC | ISA_A,
        VERSION2,
        u64::MAX,
        1024 * 1024, // usize, must be 4096-aligned
    );

    RustDefaultMachineBuilder::new(core)
        .instruction_cycle_func(Box::new(ckb_vm::cost_model::constant_cycles))
        .build()
}
```

Key points:

- `new_with_memory` takes a `usize` memory size.
- `SparseMemory::new` and `FlatMemory::new` panic on non-page-aligned sizes.
- Use `WXorXMemory<SparseMemory<u64>>` for permission-sensitive tests.

## Raw Bytecode Loading

```rust
let mut machine = build_machine();
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

Key points:

- `LoadingAction::source` is `Range<u64>`.
- `load_program_with_metadata` takes `&ProgramMetadata`, not `Option`.
- WXorX page initialisation expects page-aligned addresses and page-rounded sizes.

## Running One Step

```rust
let mut decoder = DefaultDecoder::new::<u64>(ISA_IMC | ISA_A, VERSION2);
let result = machine.step(&mut decoder);
```

Key points:

- Import `InstDecoder`; `DefaultDecoder::new` is a trait method.
- `step()` requires `&mut decoder`.

## Memory Read/Write

```rust
let addr = 0x20000u64;
let value = 42u64;

machine.memory_mut().store8(&addr, &value).unwrap();
machine.memory_mut().store16(&addr, &value).unwrap();
machine.memory_mut().store32(&addr, &value).unwrap();
machine.memory_mut().store64(&addr, &value).unwrap();

let loaded8: u64 = machine.memory_mut().load8(&addr).unwrap();
let loaded64: u64 = machine.memory_mut().load64(&addr).unwrap();
let bytes = machine.memory_mut().load_bytes(addr, 16).unwrap();
```

Key points:

- `store8/16/32/64` take `&addr` and `&value`.
- `load8/16/32/64` take `&addr` and return the register type.
- `load_bytes(addr, size)` takes plain `u64` values.

## External ELF Harness

Create a temporary crate outside the target checkout:

```toml
[dependencies]
ckb-vm = { path = "../ckb-vm" }
```

Then call the ELF parser directly:

```rust
use ckb_vm::bytes::Bytes;
use ckb_vm::elf::parse_elf;
use ckb_vm::machine::VERSION2;

let elf = Bytes::from(elf_bytes);
let metadata = parse_elf::<u64>(&elf, VERSION2);
println!("{metadata:?}");
```

This gives compile-checked evidence without modifying the audited repository.
