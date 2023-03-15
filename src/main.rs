use std::io;
use winreg::enums::*;
use winreg::RegKey;

fn main() -> io::Result<()> {
    println!("Reading some system info...");
    // last shutdown time
    // Network and IP addresses
    // type of network
    // share of the systems and their configuration
    // Get information about USER from SAM and System
    // Last password change
    // account created
    // login count
    // user ID

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // get computer name
    let cur_ver = hklm.open_subkey("SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName")?;
    let computer_name: String = cur_ver.get_value("ComputerName")?;
    println!("Computer Name = {}", computer_name);

    // get time zone
    let cur_ver_tz = hklm.open_subkey("SYSTEM\\ControlSet001\\Control\\TimeZoneInformation")?;
    let time_zone_name: String = cur_ver_tz.get_value("TimeZoneKeyName")?;
    println!("Computer time zone = {}", time_zone_name);
    let time_zone_bias: u32 = cur_ver_tz.get_value("ActiveTimeBias")?;
    println!("UTC+{}", (time_zone_bias as i32) * -1);

    // Get the status of the option NTFSdisableLastAccessUpdate
    let ntfs_access_time = hklm.open_subkey("SYSTEM\\ControlSet001\\Control\\FileSystem")?;
    let mut value_ntfs_last_access_update: u32 = ntfs_access_time
        .get_value("NtfsDisableLastAccessUpdate")
        .unwrap();
    value_ntfs_last_access_update -= 2147483648;
    println!("NTFS Last Access Time Stamp Updates");

    let mut definition_value: String = "".to_string();
    if value_ntfs_last_access_update == 0 {
        definition_value = "User Managed, Last Access Time Updates Enabled".to_string();
    } else if value_ntfs_last_access_update == 1 {
        definition_value = "User Managed, Last Access Time Updates Disabled".to_string();
    } else if value_ntfs_last_access_update == 2 {
        definition_value = "System Managed, Last Access Time Updates Enabled (Default)".to_string();
    } else if value_ntfs_last_access_update == 3 {
        definition_value = "System Managed, Last Access Time Updates Disabled".to_string();
    }

    println!(
        "Value for NtfsDisableLastAccessUpdate = {} ({}).",
        value_ntfs_last_access_update, definition_value
    );
    Ok(())
}
