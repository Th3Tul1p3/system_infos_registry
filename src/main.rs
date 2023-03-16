use datetime::*;
use std::io;
use std::time::Duration;
use winreg::enums::*;
use winreg::RegKey;
use winreg::RegValue;

fn main() -> io::Result<()> {
    println!("Reading some system info...");
    // Network and IP addresses
    // type of network
    // share of the systems and their configuration
    // Get information about USER from SAM and System
    // Last password change
    // account created
    // login count
    // user ID

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // current control set
    let select_current = hklm.open_subkey("SYSTEM\\Select")?;
    let current: u32 = select_current.get_value("Current")?;

    // get computer name
    let computername = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\ComputerName\\ComputerName"
    ))?;
    let computer_name: String = computername.get_value("ComputerName")?;
    println!("Computer Name = {}", computer_name);

    // get time zone
    let control_timezoneinformation = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\TimeZoneInformation"
    ))?;
    let time_zone_name: String = control_timezoneinformation.get_value("TimeZoneKeyName")?;
    print!("Computer time zone = {}", time_zone_name);
    let time_zone_bias: u32 = control_timezoneinformation.get_value("ActiveTimeBias")?;
    println!(" UTC+{}", (time_zone_bias as i32) * -1);

    // Get the status of the option NTFSdisableLastAccessUpdate
    let control_filesystem = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\FileSystem"
    ))?;
    let mut value_ntfs_last_access_update: u32 = control_filesystem
        .get_value("NtfsDisableLastAccessUpdate")
        .unwrap();
    value_ntfs_last_access_update -= 2147483648; // Masking 0x8000000

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

    // last shutdown time
    let control_windows = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\Windows"
    ))?;
    let shutdown_time: RegValue = control_windows.get_raw_value("ShutdownTime")?;
    let shutdown_time_iso = rawvalue_to_timestamp(shutdown_time.bytes);
    println!("Last reboot {}", split_iso_timestamp(shutdown_time_iso));

    Ok(())
}

pub fn rawvalue_to_timestamp(tmp: Vec<u8>) -> LocalDateTime {
    let bytes_to_nanos = u64::from_le_bytes(tmp.try_into().unwrap()) * 100;
    let nanos_to_secs: i64 = Duration::from_nanos(bytes_to_nanos)
        .as_secs()
        .try_into()
        .unwrap();
    let windows_base_date = LocalDate::ymd(1601, Month::January, 1).unwrap();
    let hour: i8 = 0;
    let minute: i8 = 0;
    let windows_base_time = LocalTime::hm(hour, minute).unwrap();
    let windows_base_timestamp = LocalDateTime::new(windows_base_date, windows_base_time);
    windows_base_timestamp.add_seconds(nanos_to_secs)
}

pub fn split_iso_timestamp<'a>(iso_timestamp: LocalDateTime) -> String {
    let mut string_vec: Vec<String> = Vec::new();
    iso_timestamp
        .iso()
        .to_string()
        .split("T")
        .for_each(|x| string_vec.push(x.to_string()));
    format!(
        "{} {}",
        string_vec.get(0).unwrap(),
        string_vec.get(1).unwrap()
    )
}
