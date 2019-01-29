use std::{
    io,
    ops::Deref,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle},
    ptr::null_mut,
};

use winapi::{
    shared::minwindef as mw,
    um::{handleapi as wh, processthreadsapi as wp, winnt},
};

use Error;
use WinResult;

/// An owning wrapper over a Windows handle.
///
/// Will close the inner handle on `drop`.
#[derive(Debug)]
pub struct Handle(winnt::HANDLE);

impl Handle {
    /// Takes ownership of a raw handle.
    pub unsafe fn new(handle: winnt::HANDLE) -> Handle {
        Handle(handle)
    }

    //    pub fn close(self) -> WinResult {
    //        match unsafe { wh::CloseHandle(self.into_raw_handle()) } {
    //            0 => Err(Error::last()),
    //            _ => Ok(()),
    //        }
    //    }

    /// Duplicates a handle without taking ownership.
    pub unsafe fn duplicate_from(handle: winnt::HANDLE) -> WinResult<Handle> {
        let mut new_handle = null_mut();
        let res = wh::DuplicateHandle(
            wp::GetCurrentProcess(),
            handle,
            wp::GetCurrentProcess(),
            &mut new_handle,
            0,
            mw::FALSE,
            winnt::DUPLICATE_SAME_ACCESS,
        );
        match res {
            0 => Err(Error::last_os_error()),
            _ => Ok(Handle(new_handle)),
        }
    }
}

impl AsRawHandle for Handle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0 as RawHandle
    }
}

impl Deref for Handle {
    type Target = winnt::HANDLE;
    fn deref(&self) -> &winnt::HANDLE {
        &self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let err = unsafe { wh::CloseHandle(self.0) };
        assert_ne!(err, 0, "{:?}", io::Error::last_os_error());
    }
}

impl FromRawHandle for Handle {
    unsafe fn from_raw_handle(handle: RawHandle) -> Handle {
        Handle(handle as winnt::HANDLE)
    }
}

impl IntoRawHandle for Handle {
    fn into_raw_handle(self) -> RawHandle {
        self.0 as RawHandle
    }
}
