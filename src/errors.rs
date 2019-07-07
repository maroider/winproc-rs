use failure::Fail;
use std::{ffi, fmt, io};

/// A Windows process error.
#[derive(Debug, Fail)]
pub enum Error {
    /// A Windows error.
    Os(#[cause] io::Error),
    /// No process found during a search.
    NoProcess(String),
    /// An invalid nul value was found in a UTF-8 string.
    NulError(#[cause] ffi::NulError),
    /// An invalid nul value was found in a UTF-16 string vector.
    ///
    /// The error indicates the position in the vector where the nul value was found, as well as
    /// returning the ownership of the invalid vector.
    NulErrorW { pos: usize, data: Vec<u16> },
}

impl Error {
    pub fn code(&self) -> Option<u32> {
        if let Error::Os(ref e) = self {
            Some(e.raw_os_error().unwrap() as _)
        } else {
            None
        }
    }

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
            Error::NulError(ref e) => write!(f, "Null byte error: {}", e),
            Error::NulErrorW { ref pos, ref data } => {
                write!(f, "Null byte UTF-16 error: pos {} in {:?}", pos, data)
            }
        }
    }
}

impl From<ffi::NulError> for Error {
    fn from(e: ffi::NulError) -> Error {
        Error::NulError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Os(e)
    }
}

pub type WinResult<T = ()> = Result<T, Error>;
