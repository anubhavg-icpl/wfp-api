mod app;
mod engine;


use windows::{
    core::{PCWSTR, PWSTR, GUID, HRESULT, Result},
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_APP_ID,
            FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_BLOCK, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, 
            FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWPM_FILTER_FLAGS, 
            FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_SUBLAYER0, FWP_BYTE_BLOB,
            FwpmEngineClose0, FwpmFilterDeleteByKey0, FwpmSubLayerDeleteByKey0,
            FwpmFilterGetByKey0,
        },
        Security::{
            self,
            TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};
use std::{path::Path, ptr::null_mut};
use glob::glob;

use crate::{app::open_app_id, engine::open_engine};

struct FilterInfo {
    filter_guid_v4: GUID,
    filter_guid_v6: GUID,
    sublayer_guid: GUID,
}

struct EngineHandle(HANDLE);

impl Drop for EngineHandle {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

fn create_sublayer(engine_handle: HANDLE) -> Result<GUID> {
    unsafe {
        let sublayer_guid = GUID::new()?;
        
        let name = "Calculator Network Block";
        let mut name_wide: Vec<u16> = name.encode_utf16().collect();
        name_wide.push(0);
        let description = "Blocks network access for Calculator";
        let mut desc_wide: Vec<u16> = description.encode_utf16().collect();
        desc_wide.push(0);

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_guid,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_mut_ptr()),
                description: PWSTR(desc_wide.as_mut_ptr()),
            },
            flags: 0,
            providerKey: null_mut(),
            providerData: Default::default(),
            weight: 0x100,
        };

        println!("Adding sublayer to WFP with name: {}", name);
        match FwpmSubLayerAdd0(engine_handle, &sublayer, None) {
            0 => {
                println!("Successfully added sublayer");
                Ok(sublayer_guid)
            },
            error => {
                println!("Failed to add sublayer. Error code: {:#x}", error);
                match error {
                    0x80320023 => println!("Error: Display name is required"),
                    0x80320001 => println!("Error: Invalid parameter"),
                    0x80320002 => println!("Error: Object already exists"),
                    _ => println!("Unknown error occurred"),
                }
                Err(windows::core::Error::from_win32())
            }
        }
    }
}

fn create_filter(handle: HANDLE, sublayer_guid: GUID, app_id: &mut FWP_BYTE_BLOB) -> Result<FilterInfo> {
    unsafe {
        let filter_guid_v4 = GUID::new()?;
        let filter_guid_v6 = GUID::new()?;

        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_id,
                },
            },
        };

        let name = "Calculator Network Block Filter";
        let mut name_wide: Vec<u16> = name.encode_utf16().collect();
        name_wide.push(0);
        let description = "Blocks network access for Calculator application";
        let mut desc_wide: Vec<u16> = description.encode_utf16().collect();
        desc_wide.push(0);

        println!("Creating IPv4 WFP filter...");
        let filter_v4 = FWPM_FILTER0 {
            filterKey: filter_guid_v4,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_mut_ptr()),
                description: PWSTR(desc_wide.as_mut_ptr()),
            },
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                Anonymous: FWPM_ACTION0_0::default(),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: null_mut(),
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: sublayer_guid,
            weight: Default::default(),
            numFilterConditions: 1,
            filterCondition: &mut condition,
            ..Default::default()
        };

        println!("Adding IPv4 filter...");
        match FwpmFilterAdd0(handle, &filter_v4, None, None) {
            0 => println!("Successfully added IPv4 filter"),
            error => {
                println!("Failed to add IPv4 filter. Error: {:#x}", error);
                return Err(windows::core::Error::from_win32());
            }
        }

        println!("Creating IPv6 WFP filter...");
        let filter_v6 = FWPM_FILTER0 {
            filterKey: filter_guid_v6,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ..filter_v4
        };

        println!("Adding IPv6 filter...");
        match FwpmFilterAdd0(handle, &filter_v6, None, None) {
            0 => {
                println!("Successfully added IPv6 filter");
                Ok(FilterInfo {
                    filter_guid_v4,
                    filter_guid_v6,
                    sublayer_guid,
                })
            },
            error => {
                println!("Failed to add IPv6 filter. Error: {:#x}", error);
                // Clean up the IPv4 filter if IPv6 fails
                FwpmFilterDeleteByKey0(handle, &filter_guid_v4);
                Err(windows::core::Error::from_win32())
            }
        }
    }
}

fn remove_filters(handle: HANDLE, filter_info: &FilterInfo) -> Result<()> {
    unsafe {
        println!("Removing IPv4 filter...");
        match FwpmFilterDeleteByKey0(handle, &filter_info.filter_guid_v4) {
            0 => println!("Successfully removed IPv4 filter"),
            error => println!("Failed to remove IPv4 filter: {:#x}", error),
        }

        println!("Removing IPv6 filter...");
        match FwpmFilterDeleteByKey0(handle, &filter_info.filter_guid_v6) {
            0 => println!("Successfully removed IPv6 filter"),
            error => println!("Failed to remove IPv6 filter: {:#x}", error),
        }

        println!("Removing sublayer...");
        match FwpmSubLayerDeleteByKey0(handle, &filter_info.sublayer_guid) {
            0 => println!("Successfully removed sublayer"),
            error => println!("Failed to remove sublayer: {:#x}", error),
        }

        Ok(())
    }
}

fn verify_filters(handle: HANDLE, filter_info: &FilterInfo) -> Result<bool> {
    unsafe {
        let mut filter_v4 = std::ptr::null_mut();
        let mut filter_v6 = std::ptr::null_mut();

        let v4_exists = FwpmFilterGetByKey0(
            handle, 
            &filter_info.filter_guid_v4, 
            &mut filter_v4
        ) == 0;

        let v6_exists = FwpmFilterGetByKey0(
            handle, 
            &filter_info.filter_guid_v6, 
            &mut filter_v6
        ) == 0;

        println!("IPv4 filter status: {}", if v4_exists { "Active" } else { "Not found" });
        println!("IPv6 filter status: {}", if v6_exists { "Active" } else { "Not found" });

        Ok(v4_exists && v6_exists)
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let remove_mode = args.len() > 1 && args[1] == "--remove";

    if !is_elevated() {
        println!("Program is not running with elevated privileges");
        return Err(windows::core::Error::new(
            HRESULT(-1),
            "This program requires administrative privileges"
        ));
    }
    println!("Program is running with elevated privileges");

    let handle = open_engine()?;
    let engine_handle = EngineHandle(handle);
    println!("Successfully opened engine");

    if remove_mode {
        // TODO: Implement filter removal using stored GUIDs
        println!("Filter removal requires stored GUIDs from previous installation");
        return Ok(());
    }
    
    let path = get_calculator_path().ok_or_else(|| {
        windows::core::Error::new(
            HRESULT(-1),
            "Could not find Calculator path"
        )
    })?;

    if !Path::new(&path).exists() {
        return Err(windows::core::Error::new(
            HRESULT(-1),
            "Calculator path does not exist"
        ));
    }
    println!("Verified Calculator path exists");

    let mut path_bits: Vec<u16> = path.encode_utf16().collect();
    path_bits.push(0);

    unsafe {
        let mut app_id = open_app_id(PCWSTR(path_bits.as_mut_ptr()))
    .map_err(|e| windows::core::Error::new(
        e.code(),  // Use code() instead of casting
        "Failed to open app ID"
    ))?;
        println!("Successfully got app ID");

        let sublayer_guid = create_sublayer(engine_handle.0)?;
        let filter_info = create_filter(engine_handle.0, sublayer_guid, &mut app_id)?;

        println!("\nVerifying filter installation...");
        if verify_filters(engine_handle.0, &filter_info)? {
            println!("\nFilters successfully installed and verified");
            println!("\nFilter details for future removal:");
            println!("IPv4 Filter GUID: {:?}", filter_info.filter_guid_v4);
            println!("IPv6 Filter GUID: {:?}", filter_info.filter_guid_v6);
            println!("Sublayer GUID: {:?}", filter_info.sublayer_guid);
        } else {
            println!("\nWarning: Some filters may not be installed correctly");
        }
    }

    println!("\nTo verify blocking:");
    println!("1. Open Calculator");
    println!("2. Try using Currency Converter or any online feature");
    println!("3. The connection should be blocked");
    println!("\nTo remove filters, run with --remove flag");
    
    Ok(())
}



fn get_calculator_path() -> Option<String> {
    println!("Searching for modern Calculator path...");
    let modern_path = r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_*\CalculatorApp.exe";
    
    if let Ok(paths) = glob(modern_path) {
        if let Some(Ok(path)) = paths.last() {
            println!("Found modern Calculator path");
            return Some(path.to_string_lossy().into_owned());
        }
    }

    println!("Falling back to legacy Calculator path...");
    let legacy_path = r"C:\Windows\System32\calc.exe";
    if Path::new(legacy_path).exists() {
        println!("Found legacy Calculator path");
        return Some(legacy_path.to_string());
    }

    println!("Could not find Calculator path");
    None
}

fn is_elevated() -> bool {
    unsafe {
        println!("Checking elevation status...");
        let mut handle = HANDLE::default();
        
        let token_result = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut handle as *mut _
        );

        match token_result {
            Ok(_) => {
                println!("Successfully opened process token");
                let mut elevation: Security::TOKEN_ELEVATION = Default::default();
                let mut size = 0;
                
                match Security::GetTokenInformation(
                    handle,
                    Security::TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    std::mem::size_of::<Security::TOKEN_ELEVATION>() as u32,
                    &mut size
                ) {
                    Ok(_) => {
                        let is_elevated = elevation.TokenIsElevated != 0;
                        println!("Successfully got token information. Elevation status: {}", is_elevated);
                        is_elevated
                    },
                    Err(e) => {
                        println!("Failed to get token information: {:?}", e);
                        false
                    }
                }
            },
            Err(e) => {
                println!("Failed to open process token: {:?}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_calculator_path() {
        let path = get_calculator_path();
        assert!(path.is_some(), "Calculator path should be found");
        let path_str = path.unwrap();
        assert!(Path::new(&path_str).exists(), "Calculator path should exist");
    }

    #[test]
    fn test_is_elevated() {
        let elevated = is_elevated();
        println!("Process elevation status: {}", elevated);
    }
}