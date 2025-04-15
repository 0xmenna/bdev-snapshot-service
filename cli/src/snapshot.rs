use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::raw::c_char;
use std::result::Result;

const SUCCESS: i32 = 0;
const AUTHF: i32 = -4;
const MODUNLOADED: i32 = -6;
const ACCESS_DENIED: i32 = -13;
const ENOMEM: i32 = -12;

extern "C" {
    fn sys_activate_snapshot(devname: *const c_char, password: *const c_char) -> i32;
    fn sys_deactivate_snapshot(devname: *const c_char, password: *const c_char) -> i32;
    fn compute_checksum(data: *const c_char, size: usize, seed: u32) -> u32;
}

#[derive(Debug)]
pub enum Error {
    ConversionError,
    AuthFailed,
    ModuleUnloaded,
    AccessDenied,
    OutOfMemory,
    Other(i32),
}

pub fn activate_snapshot(devname: &str, password: &str) -> Result<(), Error> {
    // Convert strings to C-compatible strings.
    let devname_c = CString::new(devname).map_err(|_| Error::ConversionError)?;
    let password_c = CString::new(password).map_err(|_| Error::ConversionError)?;

    let result = unsafe { sys_activate_snapshot(devname_c.as_ptr(), password_c.as_ptr()) };
    match result {
        SUCCESS => Ok(()),
        AUTHF => Err(Error::AuthFailed),
        MODUNLOADED => Err(Error::ModuleUnloaded),
        ACCESS_DENIED => Err(Error::AccessDenied),
        ENOMEM => Err(Error::OutOfMemory),
        _ => Err(Error::Other(result)),
    }
}

pub fn deactivate_snapshot(devname: &str, password: &str) -> Result<(), Error> {
    // Convert strings to C-compatible strings.
    let devname_c = CString::new(devname).map_err(|_| Error::ConversionError)?;
    let password_c = CString::new(password).map_err(|_| Error::ConversionError)?;

    let result = unsafe { sys_deactivate_snapshot(devname_c.as_ptr(), password_c.as_ptr()) };
    match result {
        SUCCESS => Ok(()),
        AUTHF => Err(Error::AuthFailed),
        ACCESS_DENIED => Err(Error::AccessDenied),
        ENOMEM => Err(Error::OutOfMemory),
        _ => Err(Error::Other(result)),
    }
}

const SNAPSHOT_RECORD_MAGIC: u32 = 0x50414E53;

#[repr(C)]
#[derive(Debug)]
struct SnapshotRecordHeader {
    magic: u32,
    block_number: u64,
    data_size: usize,
    checksum: u32,
}

pub fn restore_snapshot(dev_name: &str, snapshot_dir: &str) -> std::io::Result<()> {
    let dev_path = if dev_name.starts_with('/') {
        dev_name.to_string()
    } else {
        format!("/dev/{}", dev_name)
    };

    let mut dev_file = File::options().read(true).write(true).open(dev_path)?;

    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file()
            || !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("snap_c")
        {
            continue;
        }

        let mut file = File::open(&path)?;
        loop {
            let mut header_buf = [0u8; std::mem::size_of::<SnapshotRecordHeader>()];
            if file.read_exact(&mut header_buf).is_err() {
                break; // EOF or incomplete record
            }

            let header: SnapshotRecordHeader =
                unsafe { std::ptr::read(header_buf.as_ptr() as *const _) };

            if header.magic != SNAPSHOT_RECORD_MAGIC {
                eprintln!("Invalid magic in file {:?}. Skipping rest.", path);
                break;
            }

            let mut block_data = vec![0u8; header.data_size];
            file.read_exact(&mut block_data)?;

            let c_data = block_data.as_ptr() as *const c_char;
            let _checksum =
                unsafe { compute_checksum(c_data, header.data_size, header.block_number as u32) };

            println!("Header: {:?}", header);

            // if checksum != header.checksum {
            //     eprintln!(
            //         "Checksum mismatch for block {} in file {:?}. Skipping block.",
            //         header.block_number, path
            //     );
            //     continue;
            // }

            let offset = header.block_number * header.data_size as u64;
            dev_file.seek(SeekFrom::Start(offset))?;
            dev_file.write_all(&block_data)?;

            let offset = header.block_number * header.data_size as u64;
            dev_file.seek(SeekFrom::Start(offset))?;
            dev_file.write_all(&block_data)?;
        }
    }

    Ok(())
}
