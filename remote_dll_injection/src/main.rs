use clap::Parser;
use std::{path::PathBuf};
use std::fmt;
use std::ffi::{c_void, CString};
use std::mem::transmute;

use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread, LPTHREAD_START_ROUTINE, GetThreadId, WaitForSingleObject, INFINITE};
use windows::Win32::Foundation::{HANDLE, WIN32_ERROR, CloseHandle};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE, VirtualFreeEx, MEM_RELEASE, VirtualProtectEx, PAGE_READONLY, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::s;


type LPVOID = *mut c_void;

// passing Dll_Path and Pid to our program.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args{
    #[arg(short, long)]
    path: PathBuf,

    #[arg(short, long)]
    pid: u32,
}

impl fmt::Display for Args{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "File: {}, Count: {}", self.path.display(), self.pid)
    }
}

impl Args{
    pub fn parse() -> Self{
        let path = std::env::args().nth(1).and_then(|s| s.parse().ok()).expect("[-] Invalid Dll Path");
        let pid = std::env::args().nth(2).and_then(|s| s.parse().ok()).expect("[-] Invalid Pid");

        Self{path, pid}
    }
}

impl IntoIterator for Args {
    type Item = (PathBuf, u32);
    type IntoIter = std::iter::Once<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once((self.path, self.pid))
    }
}

fn main(){
    // we need two arguments one is our PID and second one is our dll path that we will injection into remote process
    let args = Args::parse();
    println!("[+] Injected path: {}\n[+] Injected Pid: {}", args.path.display(), args.pid);   

    match remote_injection(args.path, args.pid) {
        Ok(_) => {
            println!("[+] Injection process lifecycle completed successfully.");
        }
        Err(e) => {
            eprintln!("[-] Injection failed with Windows API error: {:?}", e);
        }
    }

}

#[warn(dead_code)]
fn remote_injection(dll_path: PathBuf, pid: u32) -> Result<HANDLE, WIN32_ERROR>{
    // remote injection logic will be here
    let handle= unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|err| WIN32_ERROR(err.code().0 as u32))?
    };

    let path_string = dll_path.to_string_lossy();
    let c_path = CString::new(path_string.as_ref()).expect("unable to parse filel");
    let allocated_mem = c_path.as_bytes_with_nul().len();
    let buffer_ptr = c_path.as_ptr() as *const std::ffi::c_void;
    let dllPathAddr: LPVOID = unsafe {
        VirtualAllocEx(handle, None, allocated_mem,  MEM_COMMIT, PAGE_READWRITE)
    };

    if dllPathAddr.is_null() {
        println!("[-] Failed to allocate memory in remote process.");
        unsafe { CloseHandle(handle); }
    } else {
        println!("\n[+] Allocated RW memory region in remote address: {:?}", dllPathAddr);
    }

    if(unsafe {
        WriteProcessMemory(handle, dllPathAddr, buffer_ptr, allocated_mem, None)
    }).is_err(){
        println!("[-] Failed to write dll to process");
        unsafe {
            let _ = VirtualFreeEx(handle, dllPathAddr, 0, MEM_RELEASE);
            let _ = CloseHandle(handle);
        };
    }else{
        println!("[+] code is written !");
    };

    println!("Press any key to change permission from RW to R only. . .\n");

    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    let protect_result = unsafe{
        VirtualProtectEx(handle, dllPathAddr, allocated_mem, PAGE_READONLY, &mut old_protect)
    };

    if protect_result.is_err(){
        unsafe {
            VirtualFreeEx(handle, dllPathAddr, 0, MEM_RELEASE);
        }
    }else {
        println!("[+] Permissions of memory region at 0x%p changed to PAGE_READONLY {:?}", dllPathAddr);
    };

    println!("Press any key to create thread in remote process. . .");
    
    let h_kernel32 = unsafe { 
        GetModuleHandleA(s!("kernel32.dll")).expect("Failed to get kernel32 handle") 
    };

    let load_library_addr = unsafe { 
        GetProcAddress(h_kernel32, s!("LoadLibraryA")) 
    }.expect("Failed to find LoadLibraryA");

    let thread_routine: LPTHREAD_START_ROUTINE = unsafe { 
        transmute(load_library_addr) 
    };

    let hThread = unsafe {
            CreateRemoteThread(
            handle,
            None,
            0,
            thread_routine,
            Some(dllPathAddr),
            0,
            None,
        )
    };

    match hThread {
        Ok(thread_handle) => {
            let tid = unsafe { GetThreadId(thread_handle) };
            println!("[!] Remote thread TID: {}", tid);
            
            println!("[!] Remote thread start address: {:?}", load_library_addr);
            println!("[+] DLL injected successfully.");

            unsafe {
                let _ = WaitForSingleObject(thread_handle, INFINITE);

                let _ = VirtualFreeEx(handle, dllPathAddr, 0, MEM_RELEASE);

                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(handle);
            }

        }
        Err(e) => {
            println!("[-] Failed to create remote thread: {:?}", e);
            unsafe {
                let _ = VirtualFreeEx(handle, dllPathAddr, 0, MEM_RELEASE);
                let _ = CloseHandle(handle);
            };
        }
    }
    
    Ok(handle)
}
