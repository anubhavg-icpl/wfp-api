use windows::{core::PCWSTR, Win32::NetworkManagement::WindowsFilteringPlatform::{FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB}};

pub fn open_app_id(path: PCWSTR) -> Result<FWP_BYTE_BLOB, u32> {
    let mut app_id = FWP_BYTE_BLOB::default();
    let mut app_id_ptr: *mut FWP_BYTE_BLOB = &mut app_id;
    let app_id_ptr_ptr: *mut *mut FWP_BYTE_BLOB = &mut app_id_ptr;

    let status = unsafe {
        FwpmGetAppIdFromFileName0(path, app_id_ptr_ptr)
    };

    if status != 0 {
        return Err(status)
    }

    Ok(app_id)
}
