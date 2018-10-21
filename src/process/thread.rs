use std::{
    mem,
    ops::Deref,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle},
};
use winapi::{
    shared::{
        basetsd::{DWORD_PTR, ULONG64},
        minwindef::DWORD,
    },
    um::{
        processthreadsapi::{
            GetCurrentThread,
            GetThreadId,
            GetThreadIdealProcessorEx,
            OpenThread,
            SetThreadIdealProcessor,
        },
        realtimeapiset::QueryThreadCycleTime,
        tlhelp32::{Thread32Next, THREADENTRY32},
        winbase::SetThreadAffinityMask,
        winnt::{self, PROCESSOR_NUMBER, THREAD_ALL_ACCESS},
    },
};
use Error;
use Handle;
use Process;
use WinResult;

/// A handle to a running thread.
#[derive(Debug)]
pub struct Thread {
    handle: Handle,
}

impl Thread {
    /// Creates a thread handle from a thread ID.
    pub fn from_id(id: u32) -> WinResult<Thread> {
        unsafe {
            let handle = OpenThread(THREAD_ALL_ACCESS, 0, id);
            if handle.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(Thread {
                    handle: Handle::new(handle),
                })
            }
        }
    }

    /// Returns a handle to the current thread.
    pub fn current() -> Thread {
        unsafe {
            Thread {
                handle: Handle::from_raw_handle(GetCurrentThread()),
            }
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Return's the thread's ID.
    pub fn id(&self) -> u32 {
        unsafe { GetThreadId(self.handle.as_raw_handle()) }
    }

    /// Returns the thread's cycle time.
    pub fn cycle_time(&self) -> WinResult<u64> {
        unsafe {
            let mut cycles: ULONG64 = 0;
            let ret = QueryThreadCycleTime(self.handle.as_raw_handle(), &mut cycles);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(cycles as u64)
            }
        }
    }

    /// Returns the thread's ideal processor.
    pub fn ideal_processor(&self) -> WinResult<u32> {
        unsafe {
            let mut ideal: PROCESSOR_NUMBER = mem::zeroed();
            let ret = GetThreadIdealProcessorEx(self.handle.as_raw_handle(), &mut ideal);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(ideal.Number as u32)
            }
        }
    }

    /// Sets the thread's ideal processor. On success, returns the previous ideal processor.
    pub fn set_ideal_processor(&mut self, processor: u32) -> WinResult<u32> {
        unsafe {
            let ret = SetThreadIdealProcessor(self.handle.as_raw_handle(), processor as DWORD);
            if ret == DWORD::max_value() {
                Err(Error::last_os_error())
            } else {
                Ok(ret)
            }
        }
    }

    /// Returns the thread's current affinity mask.
    pub fn affinity_mask(&self) -> WinResult<usize> {
        unsafe {
            let affinity =
                SetThreadAffinityMask(self.handle.as_raw_handle(), DWORD_PTR::max_value());
            if affinity == 0 {
                Err(Error::last_os_error())
            } else {
                let ret = SetThreadAffinityMask(self.handle.as_raw_handle(), affinity);
                if ret == 0 {
                    Err(Error::last_os_error())
                } else {
                    Ok(affinity)
                }
            }
        }
    }

    /// Sets the affinity mask of the thread. On success, returns the previous affinity mask.
    ///
    /// A thread affinity mask is a bit vector in which each bit represents a logical processor
    /// that a thread is allowed to run on. A thread affinity mask must be a subset of the process
    /// affinity mask for the containing process of a thread. A thread can only run on the
    /// processors its process can run on. Therefore, the thread affinity mask cannot specify a
    /// 1 bit for a processor when the process affinity mask specifies a 0 bit for that processor.
    ///
    /// Setting an affinity mask for a process or thread can result in threads receiving less
    /// processor time, as the system is restricted from running the threads on certain processors.
    /// In most cases, it is better to let the system select an available processor.
    ///
    /// If the new thread affinity mask does not specify the processor that is currently running
    /// the thread, the thread is rescheduled on one of the allowable processors.
    pub fn set_affinity_mask(&mut self, mask: usize) -> WinResult<usize> {
        unsafe {
            let ret = SetThreadAffinityMask(self.handle.as_raw_handle(), mask as DWORD_PTR);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(ret)
            }
        }
    }

    /// Sets the affinity of the thread to the single specified processor.
    ///
    /// If the processor index equals or exceeds the width of usize, the mask is not changed.
    /// On success, or if unchanged, returns the previous affinity mask.
    pub fn set_affinity(&mut self, processor: u8) -> WinResult<usize> {
        let processor = processor as usize;
        if processor >= mem::size_of::<usize>() * 8 {
            self.affinity_mask()
        } else {
            self.set_affinity_mask(1 << processor)
        }
    }
}

impl AsRawHandle for Thread {
    fn as_raw_handle(&self) -> winnt::HANDLE {
        self.handle.as_raw_handle()
    }
}

impl Deref for Thread {
    type Target = winnt::HANDLE;

    fn deref(&self) -> &winnt::HANDLE {
        &*self.handle
    }
}

impl FromRawHandle for Thread {
    unsafe fn from_raw_handle(handle: winnt::HANDLE) -> Thread {
        Thread {
            handle: Handle::new(handle),
        }
    }
}

impl IntoRawHandle for Thread {
    fn into_raw_handle(self) -> winnt::HANDLE {
        self.handle.into_raw_handle()
    }
}

#[derive(Debug)]
pub struct ThreadIter<'a> {
    pub(crate) process: &'a Process,
    pub(crate) snapshot: Handle,
}

impl<'a> Iterator for ThreadIter<'a> {
    type Item = WinResult<Thread>;

    fn next(&mut self) -> Option<WinResult<Thread>> {
        unsafe {
            loop {
                let mut entry: THREADENTRY32 = mem::zeroed();
                entry.dwSize = mem::size_of::<THREADENTRY32>() as DWORD;
                let ret = Thread32Next(self.snapshot.as_raw_handle(), &mut entry);
                if ret == 0 {
                    return None;
                } else {
                    if entry.th32OwnerProcessID == self.process.id() {
                        return Some(Thread::from_id(entry.th32ThreadID));
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct ThreadIdIter<'a> {
    pub(crate) process: &'a Process,
    pub(crate) snapshot: Handle,
}

impl<'a> Iterator for ThreadIdIter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        unsafe {
            loop {
                let mut entry: THREADENTRY32 = mem::zeroed();
                entry.dwSize = mem::size_of::<THREADENTRY32>() as DWORD;
                let ret = Thread32Next(self.snapshot.as_raw_handle(), &mut entry);
                if ret == 0 {
                    return None;
                } else {
                    if entry.th32OwnerProcessID == self.process.id() {
                        return Some(entry.th32ThreadID);
                    }
                }
            }
        }
    }
}

//mod tests {
//    #[allow(unused_imports)]
//    use super::*;
//
//    #[test]
//    fn enumerates_threads() {
//        let process = Process::all().unwrap().next().unwrap();
//        let threads: Vec<_> = process.threads().unwrap().collect();
//        assert_eq!(threads.is_empty(), false);
//        println!("{:?}", threads);
//    }
//}
