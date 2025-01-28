use windows::{
    core::{PCWSTR, Result},
    Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB,
    },
};

pub fn open_app_id(path: PCWSTR) -> Result<FWP_BYTE_BLOB> {
    unsafe {
        let mut app_id = std::ptr::null_mut();
        match FwpmGetAppIdFromFileName0(path, &mut app_id) {
            0 => Ok(*app_id),
            error => {
                println!("Failed to get app ID. Error: {:#x}", error);
                Err(windows::core::Error::from_win32())
            }
        }
    }
}