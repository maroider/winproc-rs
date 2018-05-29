use std::{fmt, io};

/// A Windows process error.
#[derive(Debug, Fail)]
pub enum Error {
    /// A Windows error.
    Os(#[cause] io::Error),
    /// No process found during a search.
    NoProcess(String),
}

impl Error {
    pub fn code(&self) -> Option<u32> {
        if let Error::Os(ref e) = self {
            Some(e.raw_os_error().unwrap() as _)
        } else {
            None
        }
    }

    //    pub fn description(&self) -> Option<&'static str> {
    //        if let Some(code) = self.code() {
    //            match code {
    //                31 => Some("This device is not working properly because Windows cannot load the drivers required for this device."),
    //                _ => None
    //            }
    //        } else {
    //            None
    //        }
    //    }

    /// Returns the last windows error.
    pub fn last_os_error() -> Error {
        Error::Os(io::Error::last_os_error())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Error::Os(ref e) => {
                //                if let Some(desc) = self.description() {
                //                    write!(f, "Windows error {}: {}", code, desc)
                //                } else {
                //                    write!(f, "Windows error {}", code)
                //                }
                write!(f, "Windows error: {}", e)
            }
            Error::NoProcess(ref name) => write!(f, "No process found with the name: {}", name),
        }
    }
}

pub type WinResult<T> = ::std::result::Result<T, Error>;
