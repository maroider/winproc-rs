use std::{fmt, io};

use winapi::shared::minwindef::DWORD;

#[derive(Debug, Clone, Fail)]
pub enum Error {
    Os(DWORD),
    NoProcess(String),
}

impl Error {
    pub fn code(&self) -> Option<u32> {
        if let Error::Os(code) = self {
            Some(*code)
        } else {
            None
        }
    }

    pub fn description(&self) -> Option<&'static str> {
        if let Some(code) = self.code() {
            match code {
                31 => Some("This device is not working properly because Windows cannot load the drivers required for this device."),
                _ => None
            }
        } else {
            None
        }
    }

    /// Returns the last windows error.
    pub fn last() -> Error {
        Error::Os(io::Error::last_os_error().raw_os_error().unwrap() as _)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Os(code) => {
                if let Some(desc) = self.description() {
                    write!(f, "Windows error {}: {}", code, desc)
                } else {
                    write!(f, "Windows error {}", code)
                }
            }
            Error::NoProcess(ref name) => write!(f, "No process found with the name: {}", name),
        }
    }
}

pub type WinResult<T> = ::std::result::Result<T, Error>;
