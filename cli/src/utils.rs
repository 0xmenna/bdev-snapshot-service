use std::{fs, os::raw::c_char};

pub const SUCCESS: i32 = 0;
const AUTHF: i32 = -104;
const ACCESSDENIED: i32 = -13;

pub const SNAPSHOT_RECORD_MAGIC: u32 = 0x50414E53;

extern "C" {
    pub fn sys_activate_snapshot(devname: *const c_char, password: *const c_char) -> i32;
    pub fn sys_deactivate_snapshot(devname: *const c_char, password: *const c_char) -> i32;
    pub fn compute_checksum(data: *const c_char, size: usize, seed: u32) -> u32;
    pub fn decompress_deflate(
        in_data: *const c_char,
        in_size: usize,
        out_data: *mut c_char,
        out_capacity: usize,
        out_size: *mut usize,
    ) -> i32;
}

pub fn get_password(passfile: Option<String>) -> String {
    if let Some(passfile) = passfile {
        let password = fs::read_to_string(&passfile).unwrap_or_else(|e| {
            log_error(&format!("Error reading password file {}: {}", &passfile, e));
            std::process::exit(1);
        });
        let password = password.trim();
        password.to_string()
    } else {
        log_error("Provide the password file");
        std::process::exit(1);
    }
}

pub fn log_info(msg: &str) {
    println!("[INFO] {msg}");
}

pub fn log_success(msg: &str) {
    println!("[✓] {msg}");
}

pub fn log_warning(msg: &str) {
    println!("[!] {msg}");
}

pub fn log_error(msg: &str) {
    eprintln!("[✗] {msg}");
}

pub fn log_result_activation(res: i32) {
    match res {
        SUCCESS => {
            log_success("Snapshot activated successfully.");
        }
        AUTHF => {
            log_error("Authentication failed.");
        }
        ACCESSDENIED => {
            log_error("Access denied.");
        }
        _ => {
            log_error(&format!("Error code: {}", res));
        }
    }
}

pub fn log_result_deactivation(res: i32) {
    match res {
        SUCCESS => {
            log_success("Snapshot deactivated successfully.");
        }
        AUTHF => {
            log_error("Authentication failed.");
        }
        ACCESSDENIED => {
            log_error("Access denied.");
        }
        _ => {
            log_error(&format!("Error code: {}", res));
        }
    }
}
