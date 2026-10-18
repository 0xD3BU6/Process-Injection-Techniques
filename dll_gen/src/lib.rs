use std::os::raw::c_void;
use windows::Win32::UI::WindowsAndMessaging::{
    CBS_HASSTRINGS, MB_ICONINFORMATION, MB_OK, MessageBoxW
};
use windows::core::HSTRING;
use windows::Win32::Foundation::{
    HINSTANCE, HMODULE,
};

pub type DWORD = u32;
pub type LPVOID = *mut c_void;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _hinstance: HINSTANCE,
    reason: DWORD,
    _reserved: LPVOID,
) -> i32 {
    show_msg();
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn show_msg(){
    let text = HSTRING::from("rust dll injection testing");
    let caption: HSTRING = HSTRING::from("DLL injection test");

    unsafe {
        MessageBoxW(
            None,
            &text,
            &caption,
            MB_OK | MB_ICONINFORMATION,
        )
    };
}
