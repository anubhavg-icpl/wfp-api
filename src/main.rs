use windows::{
    core::{PCWSTR, PWSTR},
    Wdk::NetworkManagement::WindowsFilteringPlatform::{FwpmEngineOpen0, FwpmFilterAdd0},
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmGetAppIdFromFileName0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0,
            FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK,
            FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            FWP_EMPTY, FWP_MATCH_EQUAL, FWP_VALUE0,
        },
        System::Rpc::RPC_C_AUTHN_DEFAULT,
    },
};

fn main() {
    let mut handle = HANDLE::default();

    unsafe {
        FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT as u32, None, None, &mut handle);

        let mut app_id = FWP_BYTE_BLOB::default();
        let app_id_ptr = &mut app_id as *mut FWP_BYTE_BLOB;
        let app_id_ptr_ptr = app_id_ptr as *mut *mut FWP_BYTE_BLOB;

        let path = String::from(
            r#"C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe\\CalculatorApp.exe"#,
        );
        let mut path_bits: Vec<u16> = path.encode_utf16().collect();

        FwpmGetAppIdFromFileName0(PCWSTR(path_bits.as_mut_ptr()), app_id_ptr_ptr);

        let name = String::from("Block layer");
        let mut name_bits: Vec<u16> = name.encode_utf16().collect();

        println!("{:?}", *app_id_ptr);

        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_id_ptr,
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
