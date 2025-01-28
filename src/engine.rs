use windows::{
    core::{GUID, Result},
    Win32::{
        Foundation::{BOOL, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineOpen0, FWPM_SESSION0, FWPM_DISPLAY_DATA0,
        },
    },
};

pub fn open_engine() -> Result<HANDLE> {
    unsafe {
        println!("Initializing WFP engine...");
        let mut handle = HANDLE::default();
        
        // Create a basic session without any special flags first
        println!("Creating basic WFP session...");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::null(),
                description: windows::core::PWSTR::null(),
            },
            flags: 0x00000001,  // FWPM_SESSION_FLAG_DYNAMIC
            txnWaitTimeoutInMSec: 0,            // No transaction timeout
            processId: 0,                       // System assigns
            sid: std::ptr::null_mut(),
            username: windows::core::PWSTR::null(),
            kernelMode: BOOL::from(false),
            sessionKey: GUID::zeroed(),
        };

        println!("Attempting to open WFP engine with basic configuration...");
        let result = FwpmEngineOpen0(
            None,                // Local machine
            10,                 // RPC_C_AUTHN_WINNT authentication service
            None,               // No auth identity
            Some(&session),     // Use our session
            &mut handle,
        );

        match result {
            0 => {
                println!("Successfully opened WFP engine");
                Ok(handle)
            },
            error => {
                println!("Failed to open WFP engine. Error: {:#x}", error);
                // Try to provide more specific error information
                match error {
                    50 => println!("Operation not supported. Check if the Windows Filtering Platform service is running."),
                    5 => println!("Access denied. Make sure you're running as Administrator."),
                    1753 => println!("Service not responding. Try restarting the Base Filtering Engine service."),
                    _ => println!("Unknown error occurred"),
                }
                Err(windows::core::Error::from_win32())
            }
        }
    }
}