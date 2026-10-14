# Windows Process Injection in Rust

A study resource for understanding Windows process injection through operating system fundamentals, Rust, and defensive analysis. It is intended as a starting point for readers studying Windows internals, malware analysis, or red team concepts, including those preparing for CRTO.

The explanations focus on how the techniques differ, what Windows must do for them to work, and how to interpret the resulting behavior. Future implementation examples will use **Rust**.

**Current scope:** this README provides the conceptual foundation and reading path. Technique walkthroughs and runnable Rust examples have not been added yet.

## Contents

- [What is process injection?](#what-is-process-injection)
- [Windows fundamentals](#windows-fundamentals)
- [How to compare techniques](#how-to-compare-techniques)
- [Technique overview](#technique-overview)
- [Understanding PE loading](#understanding-pe-loading)
- [The Rust perspective](#the-rust-perspective)
- [Detection and observation](#detection-and-observation)
- [Suggested learning path](#suggested-learning-path)

## What is process injection?

Process injection places code into another process and causes it to execute there. The host process supplies the execution context, which can make activity appear to originate from an application that did not normally contain that code. Different techniques use different memory and execution mechanisms. [MITRE ATT&CK: Process Injection](https://attack.mitre.org/techniques/T1055/)

Three concepts help keep the terminology clear:

- **Placement:** where the code or image resides in memory.
- **Execution:** which thread or callback begins running it.
- **Loading:** how executable bytes become a usable program or module.

A memory write establishes placement. It does not, by itself, establish execution. Likewise, copying a DLL's file bytes into a buffer does not automatically perform the work of the Windows loader.

Local execution is also useful to study alongside remote injection. A local example operates within its own process; remote injection crosses a process boundary. Reflective loading describes an in-memory loading mechanism and should be considered separately from the question of which process hosts it. [MITRE ATT&CK: Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)

## Windows fundamentals

### Processes and threads

A process provides resources such as its virtual address space, loaded modules, and handles. A thread is a unit of execution inside that process. Threads in the same process share its address space, while maintaining their own execution state, including registers and stacks. [Microsoft: About Processes and Threads](https://learn.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads)

This distinction explains why changing a process's memory and changing a thread's execution state are separate operations.

### Virtual addresses

A virtual address has meaning within a particular process's address space. An address observed in one process is not automatically a valid pointer in another. [Microsoft: Virtual Address Space](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-address-space)

For Rust code, a remote address should therefore remain an address associated with that target process. Casting it to a raw pointer does not make it safe to dereference in the caller.

### Handles and access rights

A process identifier identifies a process. A handle provides access to a Windows object under the rights granted to that handle. Querying information, reading memory, writing memory, and creating threads require different rights. Access checks and protected-process restrictions affect which operations can succeed. [Microsoft: Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

An access-denied result is useful evidence about the environment and requested operation. Record the failure and its context before drawing conclusions about the technique.

### Memory protections

Read, write, and execute permissions describe different capabilities of a memory page. A writable page is not necessarily executable, and an executable page is not necessarily writable. Windows applies these protections at page granularity. [Microsoft: Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)

When examining a memory region, identify its ownership, backing, protection, and lifetime. An address alone provides very little context.

## How to compare techniques

Use the same questions when reading any implementation:

| Question | What it helps explain |
| --- | --- |
| Which process owns the relevant memory? | Whether the behavior is local or crosses a process boundary. |
| What kind of content is present? | The difference between a data buffer, executable code, and a loaded PE image. |
| How is the memory represented? | Private allocations, shared mappings, and image-backed regions have different properties. |
| What starts execution? | A new thread, an existing thread, and a callback follow different execution paths. |
| What assumptions must hold? | Architecture, access rights, thread state, and initialization can determine the result. |
| What evidence is available? | Logs, memory inspection, and debugger observations answer different questions. |

These are analytical questions for understanding a technique and evaluating evidence. They also help separate a program that reports success from behavior that was actually observed.

## Technique overview

The table summarizes the main study topics. Each linked reference provides the underlying terminology or mechanism.

| Topic | Core idea | Main concept to understand |
| --- | --- | --- |
| Local execution / self injection | Code executes within the program's own process. | Local memory ownership and execution; the comparison point for remote techniques. |
| [DLL injection](https://attack.mitre.org/techniques/T1055/001/) | A DLL is introduced into another process for execution. | Module loading and the distinction between a DLL path, file contents, and a loaded module. |
| [Thread execution hijacking](https://attack.mitre.org/techniques/T1055/003/) | An existing thread's execution is redirected. | Thread context, stack state, and the effect on the thread's original work. |
| [APC injection](https://attack.mitre.org/techniques/T1055/004/) | Execution uses a thread's asynchronous procedure call mechanism. | Callback delivery and the thread conditions required for execution. |
| [Early Bird APC](https://attack.mitre.org/techniques/T1055/004/) | An APC variant associated with early execution in a newly created process. | Process initialization timing and the distinction between queuing and execution. |
| [TLS callback injection](https://attack.mitre.org/techniques/T1055/005/) | Execution is redirected through thread-local-storage callback mechanisms. | PE initialization and callbacks that can run before the usual entry point. |
| [Section view mapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views) | Processes use views of a shared memory section. | A section object, its views, and why each process can have a different virtual address for shared contents. |
| [PE injection](https://attack.mitre.org/techniques/T1055/002/) | A PE image is placed into another process's address space. | Image layout and the loading responsibilities needed for usable execution. |
| [Process hollowing](https://attack.mitre.org/techniques/T1055/012/) | A process's original executable image is replaced or altered to run different code. | The relationship between the process's apparent identity and its in-memory image. |
| [Reflective DLL loading](https://attack.mitre.org/techniques/T1620/) | An in-memory loader handles the loading of a DLL. | Loader responsibilities and how the loading mechanism relates to the host process. |

These labels describe overlapping aspects of behavior. Shared mapping, for example, describes a memory mechanism; it does not by itself specify how a thread starts executing code.

## Understanding PE loading

A Portable Executable (PE) file has headers, sections, and metadata describing how Windows should load it. Its layout on disk differs from its loaded layout in memory. Imports identify dependencies, relocations account for changes in the load address, and TLS metadata describes additional initialization behavior. [Microsoft: PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

Keep these address types distinct:

| Term | Meaning |
| --- | --- |
| File offset | A position within the file on disk. |
| Relative virtual address (RVA) | An address relative to the loaded image's base address. |
| Virtual address (VA) | An address within a process's virtual address space. |

An RVA and a file offset are not interchangeable. Understanding that distinction is essential when comparing a file parser's output with a debugger's memory view.

## The Rust perspective

Rust changes how an implementation expresses ownership and handles errors. Windows still defines the operating system behavior and API contracts.

Microsoft's [`windows` crate](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) provides Rust bindings to Windows APIs. Use the generated documentation for the version selected by an example rather than assuming every binding has the same return type or calling requirements.

### FFI and `unsafe`

Foreign Function Interface (FFI) calls and raw-pointer operations can involve requirements that Rust cannot verify. An `unsafe` block places responsibility for those requirements on the implementation; it does not validate a pointer, extend a buffer's lifetime, or grant operating system permissions. Keep the boundary small and explain the relevant invariants in a `SAFETY` comment. [The Rust Book: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)

Useful questions at an FFI boundary include:

- Does this pointer refer to valid memory in the correct address space?
- Does the buffer remain alive for as long as the API needs it?
- Are the length, alignment, and type appropriate for that buffer?
- Who owns the returned resource, and what releases it?
- Does this API return a borrowed value or transfer ownership?

### ABI and architecture

An Application Binary Interface (ABI) defines how arguments and results pass between functions. Calling conventions must match the target platform and the function being called. Rust's `"system"` ABI follows the platform's system calling convention; architecture-specific details still matter. [The Rust Reference: External Blocks](https://doc.rust-lang.org/reference/items/external-blocks.html)

Record the architecture of both the Rust program and the process being inspected. Avoid assuming that a numeric address, structure definition, or register name is portable across architectures.

### Resource and error handling

Future examples should make resource ownership explicit, keep cleanup reliable on failure paths, and preserve enough error context to explain what failed. Treat process handles, buffers, mappings, and thread state as separate resources with separate lifetimes.

A successful Rust build establishes that the code compiles. A successful API return establishes only what that API documents. Neither substitutes for observing the intended behavior.

## Detection and observation

Study execution together with the evidence it produces. Sysmon offers several relevant event types, subject to its configuration and filtering. [Microsoft: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

| Sysmon event | What it can help show |
| --- | --- |
| 1 — Process creation | Process identity, command line, and creation context. |
| 7 — Image loaded | Module loads, when this logging is enabled. |
| 8 — CreateRemoteThread | A process creating a thread in another process. |
| 10 — ProcessAccess | One process opening another process. |
| 25 — ProcessTampering | Detected process image changes associated with tampering techniques. |

Event 8 does not cover every execution mechanism. Event 10 does not, by itself, prove a remote memory write. Missing events require checking collection and filters before concluding that a behavior did not happen.

For an analysis, correlate the source process, target process, timestamps, thread activity, and available memory evidence. State what was directly observed, what is inferred, and what the data cannot establish.

## Suggested learning path

1. **Processes and memory:** understand address spaces, threads, handles, and page protections.
2. **Rust and Windows:** learn the binding types, FFI contracts, ownership, and error handling used by an example.
3. **Local behavior:** establish how to inspect memory and execution in a process you control.
4. **Remote concepts:** compare the process-boundary requirements with local behavior.
5. **Execution mechanisms:** study the differences between threads, thread contexts, and callbacks.
6. **Loading mechanisms:** understand PE layout before approaching image replacement or reflective loading.
7. **Defensive analysis:** compare expected behavior with collected events and debugger evidence.

