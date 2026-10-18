//! Small, dependency-free examples of named exports. No injection or DLL entry point.

/// An ordinary Rust function for comparing object-file symbol names.
pub fn ordinary_rust_function(value: u32) -> u32 {
    value.wrapping_add(1)
}

/// Adds two unsigned 32-bit integers, wrapping on overflow.
// SAFETY: This example reserves crto_study_add_v1 for this signature and
// implementation. Consumers must not link another definition under this name.
#[unsafe(no_mangle)]
pub extern "C" fn crto_study_add_v1(left: u32, right: u32) -> u32 {
    left.wrapping_add(right)
}

/// Returns the interface version under an explicit foreign symbol name.
// SAFETY: This example reserves crto_study_version_v1 for this signature.
#[unsafe(export_name = "crto_study_version_v1")]
pub extern "C" fn interface_version() -> u32 {
    1
}

/// Read-only interface metadata. Foreign consumers must not write to this value.
// SAFETY: This example reserves CRTO_STUDY_ABI_VERSION for a read-only u32.
#[unsafe(no_mangle)]
pub static CRTO_STUDY_ABI_VERSION: u32 = 1;
