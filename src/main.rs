mod app;
mod engine;

use windows::{
    core::{PCWSTR, PWSTR},
    Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0,
    Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK,
        FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY,
        FWP_MATCH_EQUAL, FWP_VALUE0,
    },
};

use crate::{app::open_app_id, engine::open_engine};

fn main() {
    unsafe {
        let handle = open_engine();

        let path = String::from(
            r#"C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe\\CalculatorApp.exe"#,
        );
        let mut path_bits: Vec<u16> = path.encode_utf16().collect();
        path_bits.push(0);

        let Ok(mut app_id) = open_app_id(PCWSTR(path_bits.as_mut_ptr())) else {
            println!("error getting app id");
            return;
        };

        let name = String::from("Block layer");
        let mut name_bits: Vec<u16> = name.encode_utf16().collect();
        name_bits.push(0);

        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: &mut app_id,
                },
            },
            ..Default::default()
        };

        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_bits.as_mut_ptr()),
                ..Default::default()
            },
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            numFilterConditions: 1,
            weight: FWP_VALUE0 {
                r#type: FWP_EMPTY,
                ..Default::default()
            },
            filterCondition: &mut condition,
            ..Default::default()
        };

        let add_status = FwpmFilterAdd0(handle, &filter, None, None);

        println!("{:?}", add_status);
    }
}
