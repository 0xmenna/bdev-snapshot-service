use std::ffi::CString;
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
