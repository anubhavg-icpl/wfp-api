use windows::Win32::{
    Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0,
    System::Rpc::RPC_C_AUTHN_DEFAULT,
};

pub unsafe fn open_engine() -> HANDLE {
    let mut handle = HANDLE::default();

    FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT as u32, None, None, &mut handle);
    handle
}
