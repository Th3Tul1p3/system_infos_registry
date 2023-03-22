use byteorder::{LittleEndian, ReadBytesExt};
use datetime::*;
use std::io;
use std::time::Duration;
use winreg::enums::*;
use winreg::RegKey;
use winreg::RegValue;

fn main() -> io::Result<()> {
    println!("---------- System profiling ----------");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // current control set
    let select_current = hklm.open_subkey("SYSTEM\\Select")?;
    let current: u32 = select_current.get_value("Current")?;
    println!("Current control set is {}", current);

    // get computer name
    let computername = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\ComputerName\\ComputerName"
    ))?;
    let computer_name: String = computername.get_value("ComputerName")?;
    println!("Computer Name: \t\t{}", computer_name);

    // get time zone
    let control_timezoneinformation = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Control\\TimeZoneInformation"
    ))?;
    let time_zone_name: String = control_timezoneinformation.get_value("TimeZoneKeyName")?;
    print!("Computer time zone: \t{}", time_zone_name);
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
    println!(
        "Last reboot (in fact restart) {}",
        split_iso_timestamp(shutdown_time_iso)
    );

    // Interfacs and their IP addresses
    let interfaces = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Services\\Tcpip\\Parameters\\Interfaces"
    ))?;
    for interface in interfaces.enum_keys().map(|x| x.unwrap()) {
        let subkey = interfaces.open_subkey(interface.clone()).unwrap();
        for k in subkey.enum_keys().map(|x| x.unwrap()) {
            println!("Interface GUID: \t{}", interface);
            let sub_subkey = subkey.open_subkey(k).unwrap();
            let dhcp_ip_address: String;
            match sub_subkey.get_value("DhcpIPAddress") {
                Ok(value) => {
                    dhcp_ip_address = value;
                    println!("DhcpIPAddress: \t\t{}", dhcp_ip_address);
                }
                Err(_e) => (),
            };
            let dhcp_domain: String;
            match sub_subkey.get_value("DhcpDomain") {
                Ok(value) => {
                    dhcp_domain = value;
                    println!("DhcpDomain: \t\t{}", dhcp_domain);
                }
                Err(_e) => (),
            };
            println!("");
        }
    }

    // Network and IP addresses and type of network
    let network_profiles =
        hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")?;

    for profile in network_profiles.enum_keys().map(|x| x.unwrap()) {
        let item = network_profiles.open_subkey(profile.clone()).unwrap();
        let description: String = item.get_value("Description")?;
        let profile_name: String = item.get_value("ProfileName")?;
        let managed: u32 = item.get_value("Managed")?;
        let date_created: RegValue = item.get_raw_value("DateCreated")?;
        let date_last_connected: RegValue = item.get_raw_value("DateLastConnected")?;
        let name_type: u32 = item.get_value("NameType")?;

        println!("Profile GUID: \t\t{}", profile);
        println!("Description: \t\t{}", description);
        println!("Profile Name: \t\t{}", profile_name);
        println!("Managed: \t\t{}", (managed == 1));
        print!("Date of creation: \t");
        bin_to_systemtime(date_created.bytes);
        print!("Last Connection: \t");
        bin_to_systemtime(date_last_connected.bytes);

        if managed == 1 {
            find_profile_guid_print_mac(
                profile,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
            );
        } else {
            find_profile_guid_print_mac(profile, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged");
        }

        print!("Type of connection: \t");
        match name_type {
            53 => println!("VPN"),
            71 => println!("Wireless"),
            6 => println!("Wired "),
            23 => println!("Broadband (3g)"),
            _ => println!("unknow type"),
        }
        println!("");
    }

    // get shares details
    let lanman_server = hklm.open_subkey(format!(
        "{}{}{}",
        "SYSTEM\\ControlSet00",
        current.to_string(),
        "\\Services\\LanmanServer\\Shares"
    ))?;

    for share in lanman_server.enum_values().map(|x| x.unwrap()) {
        let share_string = share.1.to_string().replace("\"", "");
        let share_arrays_values = share_string.split("\\n").collect::<Vec<&str>>();
        println!("{}", share.0);
        for val in share_arrays_values.iter() {
            let val_split = val.split("=").collect::<Vec<&str>>();
            print!("{}:", val_split.get(0).unwrap());
            if val_split.get(0).unwrap().len() < 7 {
                print!("\t\t");
            } else {
                print!("\t");
            }
            if *val_split.get(0).unwrap() == "CSCFlags" {
                print!("{}", val_split.get(1).unwrap());
                let tmp: u32 = val_split.get(1).unwrap().parse::<u32>().unwrap();
                match  tmp{
                    0 => println!(", By default the user needs to indicate the files that he wants to cache"),
                    16 => println!(", Automatic caching documents"),
                    32 => println!(", Automatic caching documents (optimize for performance)"),
                    48 => println!(", Cache is disabled"),
                    2048 => println!(", On Win 7 & 8 is the default setting until you disable “Simple file sharing” or use the “advanced” sharing option"),
                    768 => println!(", Shared Print devices"),
                    _ => println!(", unknow code"),
                }
                continue;
            }
            println!("{}", val_split.get(1).unwrap());
        }
    }

    Ok(())
}

pub fn find_profile_guid_print_mac(profile: String, path_to_hklm: &str) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let network_signature_unmanaged = hklm.open_subkey(path_to_hklm).unwrap();

    for signature in network_signature_unmanaged.enum_keys().map(|x| x.unwrap()) {
        let item = network_signature_unmanaged
            .open_subkey(signature.clone())
            .unwrap();
        let values: String = item.get_value("ProfileGuid").unwrap();
        if values == profile {
            let mac = item.get_raw_value("DefaultGatewayMac").unwrap().bytes;
            if mac.len() != 0 {
                println!(
                    "DefaultGatewayMac: \t{:X?}-{:X?}-{:X?}-{:X?}-{:X?}-{:X?}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            }
        }
    }
}

pub fn bin_to_systemtime(bin_value: Vec<u8>) {
    let mut year: &[u8] = &[bin_value[0], bin_value[1]];
    let year: u16 = year.read_u16::<LittleEndian>().unwrap();
    let mut month: &[u8] = &[bin_value[2], bin_value[3]];
    let month: u16 = month.read_u16::<LittleEndian>().unwrap();
    let mut day_of_week: &[u8] = &[bin_value[4], bin_value[5]];
    let num = day_of_week.read_u16::<LittleEndian>().unwrap();
    let mut day: &[u8] = &[bin_value[6], bin_value[7]];
    let day: u16 = day.read_u16::<LittleEndian>().unwrap();
    let mut hour: &[u8] = &[bin_value[8], bin_value[9]];
    let hour: u16 = hour.read_u16::<LittleEndian>().unwrap();
    let mut minute: &[u8] = &[bin_value[10], bin_value[11]];
    let minute: u16 = minute.read_u16::<LittleEndian>().unwrap();
    let mut second: &[u8] = &[bin_value[12], bin_value[13]];
    let second: u16 = second.read_u16::<LittleEndian>().unwrap();

    print!("{:2}.{:2}.{:2} ", day, month, year);
    match num {
        0 => print!("Sun "),
        1 => print!("Mon "),
        2 => print!("Tue "),
        3 => print!("Wed "),
        4 => print!("Thu "),
        5 => print!("Fri "),
        6 => print!("Sat "),
        _ => println!(""),
    }
    println!("{:2}:{:2}:{:2} ", hour, minute, second);
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
