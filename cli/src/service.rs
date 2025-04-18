use crate::utils::{self, log_info, SNAPSHOT_RECORD_MAGIC, SUCCESS};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::raw::c_char;

pub fn activate_snapshot(devname: &str, password: &str) {
    let devname_c = CString::new(devname);
    if let Err(_) = devname_c {
        utils::log_error("Failed to convert device name to CString");
        return;
    }
    let password_c = CString::new(password);
    if let Err(_) = password_c {
        utils::log_error("Failed to convert password to CString");
        return;
    }
    let devname_c = devname_c.unwrap();
    let password_c = password_c.unwrap();

    utils::log_info(&format!("Activating snapshot for device `{}`...", devname));
    let result = unsafe { utils::sys_activate_snapshot(devname_c.as_ptr(), password_c.as_ptr()) };

    utils::log_result_activation(result);
}

pub fn deactivate_snapshot(devname: &str, password: &str) {
    let devname_c = CString::new(devname);
    let password_c = CString::new(password);
    if let Err(_) = devname_c {
        utils::log_error("Failed to convert device name to CString");
        return;
    }
    if let Err(_) = password_c {
        utils::log_error("Failed to convert password to CString");
        return;
    }
    let devname_c = devname_c.unwrap();
    let password_c = password_c.unwrap();

    utils::log_info(&format!(
        "Deactivating snapshot for device `{}`...",
        devname
    ));
    let result = unsafe { utils::sys_deactivate_snapshot(devname_c.as_ptr(), password_c.as_ptr()) };

    utils::log_result_deactivation(result);
}

#[repr(C)]
#[derive(Debug)]
struct SessionFileHeader {
    magic: u32,
    block_size: u32,
}

#[repr(C)]
#[derive(Debug)]
struct SnapshotRecordHeader {
    block_number: u64,
    compressed_size: u32,
    is_compressed: bool,
    data_size: u32,
    checksum: u32,
}

pub fn restore_snapshot(dev_name: &str, snapshot_dir: &str) -> std::io::Result<()> {
    let dev_path = if dev_name.starts_with('/') {
        dev_name.to_string()
    } else {
        format!("/dev/{}", dev_name)
    };

    let mut dev_file = File::options().read(true).write(true).open(&dev_path)?;

    let entries = fs::read_dir(snapshot_dir)?;
    utils::log_info(&format!(
        "Scanning snapshot directory `{}`...",
        snapshot_dir
    ));

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_string_lossy();

        if !path.is_file() || !file_name.starts_with("snap_c") {
            continue;
        }

        utils::log_info(&format!("Restoring from snapshot file `{}`", file_name));

        let mut file = File::open(&path)?;
        let mut file_header_buf = [0u8; std::mem::size_of::<SessionFileHeader>()];
        file.read_exact(&mut file_header_buf)?;
        let session_header: SessionFileHeader =
            unsafe { std::ptr::read(file_header_buf.as_ptr() as *const _) };

        if session_header.magic != SNAPSHOT_RECORD_MAGIC {
            utils::log_warning(&format!("Invalid magic in file `{}`. Skipping.", file_name));
            continue;
        }

        log_info(&format!("Block size = {}", session_header.block_size));

        loop {
            let mut header_buf = [0u8; std::mem::size_of::<SnapshotRecordHeader>()];
            if file.read_exact(&mut header_buf).is_err() {
                break; // End of file
            }

            let header: SnapshotRecordHeader =
                unsafe { std::ptr::read(header_buf.as_ptr() as *const _) };

            log_info(&format!(
                "Processing block {}: compressed size = {}, compressed = {}, data size = {}, checksum = {}",
                header.block_number,
                header.compressed_size,
                header.is_compressed,
                header.data_size,
                header.checksum
            ));

            let mut data = vec![0u8; header.data_size as usize];

            if header.is_compressed {
                let mut comp_data = vec![0u8; header.compressed_size as usize];
                file.read_exact(&mut comp_data)?;
                let mut decompressed_size = 0;

                let result = unsafe {
                    utils::decompress_deflate(
                        comp_data.as_ptr() as *const c_char,
                        header.compressed_size as usize,
                        data.as_mut_ptr() as *mut c_char,
                        header.data_size as usize,
                        &mut decompressed_size,
                    )
                };

                if result != SUCCESS {
                    utils::log_warning(&format!(
                        "Decompression failed for block {} in `{}`. Skipping.",
                        header.block_number, file_name
                    ));
                    continue;
                }
            } else {
                file.read_exact(&mut data)?;
            }

            let checksum = unsafe {
                utils::compute_checksum(
                    data.as_ptr() as *const c_char,
                    header.data_size as usize,
                    header.block_number as u32,
                )
            };

            if checksum != header.checksum {
                utils::log_warning(&format!(
                    "Checksum mismatch at block {} in `{}`. Skipping.",
                    header.block_number, file_name
                ));
                continue;
            }

            let offset = header.block_number * session_header.block_size as u64;
            dev_file.seek(SeekFrom::Start(offset))?;
            dev_file.write_all(&data)?;
        }

        utils::log_success(&format!("Snapshot `{}` successfully restored.", file_name));
    }

    utils::log_success("All snapshot files have been restored.");
    Ok(())
}
