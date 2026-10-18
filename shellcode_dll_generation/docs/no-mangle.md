# Understanding `#[no_mangle]` and `#[unsafe(no_mangle)]` in Rust

**Official documentation exists.** The [Rust Reference](https://doc.rust-lang.org/reference/abi.html#the-no_mangle-attribute) defines the attribute, and the [Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-attributes.html) explains its newer syntax. This is an independent learning guide connecting those rules to compiled symbols, a working library, and Windows DLL development.

The accompanying [example project](../no_mangle_examples/) has no external dependencies. It exports arithmetic functions and read-only metadata, so the interface can be inspected and tested without shellcode or injection.

## Contents

- [Start with a complete declaration](#start-with-a-complete-declaration)
- [What is name mangling?](#what-is-name-mangling)
- [Four different decisions](#four-different-decisions)
- [Why is an attribute unsafe?](#why-is-an-attribute-unsafe)
- [Old syntax, new syntax, and editions](#old-syntax-new-syntax-and-editions)
- [An unsafe attribute is not an unsafe function](#an-unsafe-attribute-is-not-an-unsafe-function)
- [Build the working example](#build-the-working-example)
- [Inspect the actual symbols](#inspect-the-actual-symbols)
- [Choose a different exported name](#choose-a-different-exported-name)
- [Exporting a static](#exporting-a-static)
- [The ABI still needs suitable types](#the-abi-still-needs-suitable-types)
- [Windows DLLs and DllMain](#windows-dlls-and-dllmain)
- [Importing is different from exporting](#importing-is-different-from-exporting)
- [Generics and concrete wrappers](#generics-and-concrete-wrappers)
- [Migration and troubleshooting](#migration-and-troubleshooting)
- [What was verified](#what-was-verified)

## Start with a complete declaration

```rust
// SAFETY: This library reserves crto_study_add_v1 for this implementation.
// A consumer must not link a competing definition under the same name.
#[unsafe(no_mangle)]
pub extern "C" fn crto_study_add_v1(left: u32, right: u32) -> u32 {
    left.wrapping_add(right)
}
```

This declares a function with an intentional binary name, an explicit calling convention, and ordinary Rust visibility. Addition wraps on overflow, so this example does not introduce an overflow panic at the foreign-call boundary.

The function's name becomes part of its external interface. A consumer looking up `crto_study_add_v1` depends on that spelling. Changing it later is an interface change even if the calculation stays the same.

## What is name mangling?

Source identifiers live in namespaces. Two modules can each contain a function called `value`:

```rust
pub mod first {
    pub fn value() -> u32 { 1 }
}

pub mod second {
    pub fn value() -> u32 { 2 }
}
```

Compiled code needs symbols that distinguish those functions. Rust encodes information into generated names rather than treating both as the same bare `value` symbol. The linker uses those names when connecting references to definitions. [The rustc book: Symbol Mangling](https://doc.rust-lang.org/rustc/symbol-mangling/index.html)

A tool may demangle the encoded name into a readable Rust path. Seeing a friendly name in a debugger therefore does not establish that the binary contains an unmangled export with that exact spelling. Inspect the raw symbol or export table when that distinction matters.

## Four different decisions

| Part of a declaration or build | What it controls |
| --- | --- |
| `pub` | Whether Rust code can access an item through the applicable module/privacy rules. |
| `extern "C"` | The function's calling convention for its target platform. |
| `#[unsafe(no_mangle)]` | The item's unmangled symbol name and associated export behavior. |
| `crate-type = ["cdylib"]` | Building a system-facing dynamic library rather than an ordinary Rust library artifact. |

`pub` alone does not define a foreign ABI or promise a stable binary name. A public Rust function can still have a Rust-generated symbol. [Rust Reference: Visibility and Privacy](https://doc.rust-lang.org/reference/visibility-and-privacy.html)

Similarly, choosing `extern "C"` does not by itself request an unmangled export. Choosing an unmangled name does not, by itself, select the C ABI. These declarations solve different interface problems.

Rust's ordinary ABI has no stability guarantee. The C ABI follows the target's C calling convention; it is not a single machine-independent instruction-level interface. [Rust Reference: External Blocks and ABIs](https://doc.rust-lang.org/reference/items/external-blocks.html#abi)

`no_mangle` can expose a symbol even when the Rust item is not declared `pub`. Rust privacy is not a security boundary around binary symbols. In an intentional public interface, using `pub` also makes that intent clear to Rust readers.

## Why is an attribute unsafe?

An externally visible symbol can interact with code outside the defining Rust module or crate. If a library claims a name already used by another definition, linking can fail, or symbol resolution can connect a caller to an incompatible implementation. The latter can produce undefined behavior.

Rust cannot generally prove that a chosen name is appropriate across every library and execution environment into which the artifact might be loaded. The developer must maintain that contract. The wrapper makes this obligation explicit; it does not check the contract automatically. [RFC 3325: Unsafe Attributes](https://rust-lang.github.io/rfcs/3325-unsafe-attributes.html)

For the example, `crto_study_` is an intentionally chosen prefix, and `_v1` identifies an interface version. Those choices reduce accidental collisions and make interface evolution easier to discuss. They do not mathematically guarantee uniqueness across arbitrary third-party code.

A useful safety comment records who owns the name and the interface it represents. Writing only “safe because it compiles” does not address the linking obligation.

## Old syntax, new syntax, and editions

| Situation | Relevant syntax |
| --- | --- |
| Older examples written for pre-2024 editions | Often use `#[no_mangle]`. |
| Rust 1.82 and later, including earlier editions | Support `#[unsafe(no_mangle)]`. |
| A crate using edition 2024 | Requires the unsafe wrapper for this attribute. |

The newer spelling does not request a different calling convention or a different exported name. It explicitly marks the attribute's safety obligation. Earlier-edition code may still use the old spelling, subject to its lint settings. [Rust Edition Guide: Unsafe Attributes](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-attributes.html)

For example, this older spelling is rejected when compiled as edition 2024:

```rust
#[no_mangle]
pub extern "C" fn study_old_name() {}
```

The relevant diagnostic is:

```text
error: unsafe attribute used without unsafe
```

The correction is an attribute wrapper, not an `unsafe` block around the function body:

```rust
// SAFETY: This example owns study_old_name in its intended link environment.
#[unsafe(no_mangle)]
pub extern "C" fn study_old_name() {}
```

The edition comes from the crate's configuration, such as `edition = "2024"` in Cargo.toml. It is separate from the compiler's version number.

## An unsafe attribute is not an unsafe function

These uses of `unsafe` have different jobs:

| Form | Responsibility being expressed |
| --- | --- |
| `#[unsafe(no_mangle)]` | The safety conditions for applying that attribute. |
| `unsafe fn ...` | A function's caller must uphold additional safety requirements. |
| `unsafe { ... }` | An unsafe operation is performed with its requirements upheld. |
| `unsafe extern "C" { ... }` | Foreign declarations must correctly describe the linked interface. |

An unsafe attribute does not automatically make the function unsafe to call from Rust or authorize unsafe operations in its body. Attributes attach metadata to items; the wrapper acknowledges an attribute-specific obligation. [Rust Reference: Attribute Safety](https://doc.rust-lang.org/reference/attributes.html#safety)

For our arithmetic export, an ordinary Rust call is valid without an unsafe block:

```rust
// This function is shown alongside the earlier crto_study_add_v1 definition.
fn use_from_rust() {
    let result = crto_study_add_v1(2, 3);
    assert_eq!(result, 5);
}
```

Obtaining and calling a function address through a dynamic-loading interface is a separate operation with its own type and lifetime requirements.

## Build the working example

The [Cargo manifest](../no_mangle_examples/Cargo.toml) contains:

```toml
[package]
name = "study_exports_demo"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
crate-type = ["cdylib"]
```

`cdylib` produces a system dynamic library: a DLL on Windows, a `.so` on Linux, or a `.dylib` on macOS. A Rust `dylib` targets Rust dynamic-linking use cases and is a different choice. An `rlib` is not a DLL that a normal dynamic loader can open. [Rust Reference: Linkage](https://doc.rust-lang.org/reference/linkage.html)

From the `shellcode_dll_generation` directory:

```text
cargo build --offline --manifest-path no_mangle_examples/Cargo.toml
python no_mangle_examples/verify.py
```

The Python script locates the native debug library relative to its own directory. To inspect a different build, pass its library path as the first argument. Rust, Python, and the library must have compatible architectures.

Expected output:

```text
add(2, 3) = 5
add(0xffffffff, 1) = 0
version() = 1
CRTO_STUDY_ABI_VERSION = 1
All native export checks passed.
```

The [complete verification script](../no_mangle_examples/verify.py) uses `ctypes.CDLL` for the library's C ABI and explicitly declares `c_uint32` arguments and results. Without those declarations, a foreign caller can interpret values incorrectly even when it finds the right function name. [Python documentation: ctypes](https://docs.python.org/3/library/ctypes.html)

## Inspect the actual symbols

An object file shows what the compiler emitted before final linking. On a system with GNU `nm`, run:

```text
rustc --edition=2024 --crate-type=rlib --crate-name study_symbols --emit=obj no_mangle_examples/src/lib.rs -o study_symbols.o
nm --defined-only study_symbols.o
```

The example includes `ordinary_rust_function` for comparison. In the tested object, it has an encoded Rust symbol. The intentional exports appear under their chosen names:

```text
CRTO_STUDY_ABI_VERSION
crto_study_add_v1
crto_study_version_v1
```

Exact mangled spellings, addresses, and tool formatting are not the interface contract. On Linux, inspect the final shared library's dynamic symbols separately:

```text
nm -D --defined-only no_mangle_examples/target/debug/libstudy_exports_demo.so
```

The tested final library exposes the three names above. The ordinary Rust function is not exposed in that dynamic table. These are observations of this example and toolchain, not promises about every crate or linker configuration.

The compiler supports separate object-file and linked-output generation; examining one is not equivalent to examining the other. [The rustc book: Output Types](https://doc.rust-lang.org/rustc/command-line-arguments.html#--emit-specifies-the-types-of-output-files-to-generate)

For a Windows DLL, use a Visual Studio Developer Command Prompt with the appropriate tools installed:

```text
dumpbin /exports no_mangle_examples\target\debug\study_exports_demo.dll
```

`/EXPORTS` examines the DLL's exported definitions. Object-file symbols, debug symbols, and a DLL's export table are different views of the artifact. [Microsoft: DUMPBIN /EXPORTS](https://learn.microsoft.com/en-us/cpp/build/reference/exports)

## Choose a different exported name

`export_name` separates the Rust identifier from the foreign symbol:

```rust
// SAFETY: This library reserves crto_study_version_v1 for this signature.
#[unsafe(export_name = "crto_study_version_v1")]
pub extern "C" fn interface_version() -> u32 {
    1
}
```

Rust source calls `interface_version`. A foreign caller looks up `crto_study_version_v1`. Use this attribute instead of adding `no_mangle` to the same item. Both attributes participate in naming contracts and require the unsafe wrapper in edition 2024. [Rust Reference: export_name](https://doc.rust-lang.org/reference/abi.html#the-export_name-attribute)

## Exporting a static

The working library also defines:

```rust
// SAFETY: This example reserves this name for a read-only u32.
#[unsafe(no_mangle)]
pub static CRTO_STUDY_ABI_VERSION: u32 = 1;
```

The Python verifier reads it as `ctypes.c_uint32.in_dll(...)`. Consumers must respect its type and read-only contract. This is a data symbol, so it is read rather than invoked as a function.

An immutable exported value is not an invitation to mutate Rust-owned storage through a foreign pointer. A mutable global introduces additional aliasing and synchronization questions; this example deliberately uses read-only metadata.

## The ABI still needs suitable types

An agreed name does not describe arguments, results, ownership, or memory layout to the caller. The foreign interface must specify these independently.

| Interface choice | What the consumer needs to know |
| --- | --- |
| `u32` parameters and result | The corresponding unsigned 32-bit representation. |
| A pointer and a length | Valid ranges, ownership, lifetime, and any null-pointer rules. |
| A structure | Its specified layout and the layout of every field. |
| Allocated output | Which component releases it, and how. |

Avoid exposing Rust `String`, `Vec`, `&str`, or an ordinary Rust `Result` as though a C caller already understands their representation and ownership. An FFI adapter should define an appropriate external representation and translate it internally. Also decide how errors and panics are handled at the boundary; naming attributes do not provide that policy. [The Rustonomicon: FFI](https://doc.rust-lang.org/nomicon/ffi.html)

For a simple structure, a layout declaration can be appropriate:

```rust
#[repr(C)]
pub struct StudyPair {
    pub left: u32,
    pub right: u32,
}
```

`#[repr(C)]` addresses layout; it does not export a symbol, make every possible field FFI-compatible, or validate a pointer to a `StudyPair`. [Rust Reference: C Representation](https://doc.rust-lang.org/reference/type-layout.html#the-c-representation)

## Windows DLLs and DllMain

For an explicitly called library function, define an export and an agreed ABI, then verify the final DLL export name. Windows `GetProcAddress` uses the exported spelling, including case. Resolving an address still requires the caller to use the correct function type. [Microsoft: GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

Use the ABI required by the interface. `extern "system"` follows the system convention and differs from `extern "C"` for non-variadic functions on 32-bit x86 Windows. They use the same calling convention on Windows x64. Our example explicitly uses the C ABI, matching its Python `CDLL` caller.

An exported function and a DLL initialization callback have different roles. Applying `no_mangle` to a function named `DllMain` does not by itself establish how the toolchain configures the DLL's entry point. Initialization also runs under loader-specific restrictions. The example here intentionally exports callable functions without defining `DllMain`. [Microsoft: DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)

## Importing is different from exporting

An external block declares an interface defined elsewhere. `link_name` lets a Rust declaration refer to a differently named foreign symbol:

```rust
// Declaration only: a consumer must also arrange linkage to the defining library.
unsafe extern "C" {
    #[link_name = "crto_study_add_v1"]
    pub fn imported_add(left: u32, right: u32) -> u32;
}
```

This does not define another implementation or export a wrapper. It introduces a Rust declaration called `imported_add`. The declaration's ABI and types must match the definition, and a call through this declaration requires an unsafe context. [Rust Reference: External Blocks](https://doc.rust-lang.org/reference/items/external-blocks.html)

## Generics and concrete wrappers

A generic function describes a family of potential instantiations. A foreign interface needs concrete signatures and unambiguous names. Prefer a concrete exported wrapper that calls a Rust helper internally, as our `u32` example does.

Placing a naming attribute on a generic item is not a way to create a universal callable ABI for every `T`. Compiler diagnostics and attribute restrictions should be checked for the toolchain in use. The exported interface should already state the concrete types its consumer can pass.

## Migration and troubleshooting

For an existing crate, review attribute sites with the `unsafe_attr_outside_unsafe` lint. During an edition migration, `cargo fix --edition` can assist with syntax updates. An automated edit does not establish that the chosen symbol name or signature is sound. [The rustc book: unsafe_attr_outside_unsafe](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html#unsafe-attr-outside-unsafe)

| Symptom | Check |
| --- | --- |
| “unsafe attribute used without unsafe” | The crate edition and the `#[unsafe(...)]` wrapper. |
| The function exists in source but cannot be found by name | The final artifact's exports, exact spelling, and the library file actually loaded. |
| The library cannot load | Target architecture, dependencies, and artifact type. |
| Name lookup succeeds but a call fails | Calling convention, arguments, result type, and lifetime/ownership requirements. |
| A duplicate-symbol link error | Other definitions claiming the same name. |
| A debugger displays a friendly Rust path | Whether that tool is demangling its output. |

## What was verified

The accompanying example was built on Linux x86_64 with Rust 1.92.0. Its object symbols and final dynamic exports were inspected, and the Python verifier successfully called both named functions and read the static value.

The old and wrapped attribute spellings were also checked under editions 2021 and 2024 using the installed compiler. Windows commands describe the equivalent inspection workflow; this environment has not built or executed the Windows DLL.

This guide is an independently written tutorial, not official Rust documentation. The linked Rust Reference remains the authority for language rules, and the Edition Guide explains migration behavior.

[Return to shellcode and DLL foundations](../README.md)
