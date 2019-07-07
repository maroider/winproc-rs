use crate::{Error, Handle, Process, WinResult};
use std::{
    mem,
    ops::Deref,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle},
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
            GetThreadPriority,
            OpenThread,
            ResumeThread,
            SetThreadIdealProcessor,
            SetThreadPriority,
            SuspendThread,
            TerminateThread,
        },
        realtimeapiset::QueryThreadCycleTime,
        tlhelp32::{Thread32Next, THREADENTRY32},
        winbase::{
            SetThreadAffinityMask,
            THREAD_MODE_BACKGROUND_BEGIN,
            THREAD_MODE_BACKGROUND_END,
            THREAD_PRIORITY_ABOVE_NORMAL,
            THREAD_PRIORITY_BELOW_NORMAL,
            THREAD_PRIORITY_HIGHEST,
            THREAD_PRIORITY_IDLE,
            THREAD_PRIORITY_LOWEST,
            THREAD_PRIORITY_NORMAL,
            THREAD_PRIORITY_TIME_CRITICAL,
        },
        winnt::{self, PROCESSOR_NUMBER, THREAD_ALL_ACCESS},
    },
};

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
                handle: Handle::from_raw_handle(GetCurrentThread() as RawHandle),
            }
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Return's the thread's ID.
    pub fn id(&self) -> u32 {
        unsafe { GetThreadId(self.handle.as_raw_handle() as winnt::HANDLE) }
    }

    /// Returns the thread's cycle time.
    pub fn cycle_time(&self) -> WinResult<u64> {
        unsafe {
            let mut cycles: ULONG64 = 0;
            let ret =
                QueryThreadCycleTime(self.handle.as_raw_handle() as winnt::HANDLE, &mut cycles);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(cycles as u64)
            }
        }
    }

    /// Returns the priority level of the thread.
    ///
    /// The handle must have the `THREAD_QUERY_INFORMATION` or `THREAD_QUERY_LIMITED_INFORMATION`
    /// access right.
    pub fn priority(&self) -> WinResult<PriorityLevel> {
        unsafe {
            let ret = GetThreadPriority(self.handle.as_raw_handle() as winnt::HANDLE);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(PriorityLevel::from_code(ret as _))
            }
        }
    }

    /// Sets the priority level of the thread.
    ///
    /// The handle must have the `THREAD_SET_INFORMATION` or `THREAD_SET_LIMITED_INFORMATION`
    /// access right.
    pub fn set_priority(&mut self, priority: PriorityLevel) -> WinResult {
        unsafe {
            let ret = SetThreadPriority(
                self.handle.as_raw_handle() as winnt::HANDLE,
                priority.as_code() as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Begins background processing mode.
    ///
    /// **This can be initiated only if the handle refers to the current thread.**
    ///
    /// The system lowers the resource scheduling priorities of the thread so that it can perform
    /// background work without significantly affecting activity in the foreground.
    ///
    /// The function fails if the thread is already in background processing mode.
    ///
    /// The handle must have the `THREAD_SET_INFORMATION` or `THREAD_SET_LIMITED_INFORMATION`
    /// access right.
    pub fn start_background_mode(&mut self) -> WinResult {
        unsafe {
            let ret = SetThreadPriority(
                self.handle.as_raw_handle() as winnt::HANDLE,
                THREAD_MODE_BACKGROUND_BEGIN as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Ends background processing mode.
    ///
    /// **This can be initiated only if the handle refers to the current thread.**
    ///
    /// The system restores the resource scheduling priorities of the thread as
    /// they were before the thread entered background processing mode.
    ///
    /// The function fails if the thread is not in background processing mode.
    ///
    /// The handle must have the `THREAD_SET_INFORMATION` or `THREAD_SET_LIMITED_INFORMATION`
    /// access right.
    pub fn end_background_mode(&mut self) -> WinResult {
        unsafe {
            let ret = SetThreadPriority(
                self.handle.as_raw_handle() as winnt::HANDLE,
                THREAD_MODE_BACKGROUND_END as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Suspends the thread.
    ///
    /// If the function succeeds, the return value is the thread's previous suspend count.
    ///
    /// The handle must have the `THREAD_SUSPEND_RESUME` access right.
    pub fn suspend(&mut self) -> WinResult<u32> {
        unsafe {
            let ret = SuspendThread(self.handle.as_raw_handle() as winnt::HANDLE);
            if ret == u32::max_value() {
                Err(Error::last_os_error())
            } else {
                Ok(ret)
            }
        }
    }

    /// Resumes the thread.
    ///
    /// If the function succeeds, the return value is the thread's previous suspend count.
    ///
    /// The handle must have the `THREAD_SUSPEND_RESUME` access right.
    pub fn resume(&mut self) -> WinResult<u32> {
        unsafe {
            let ret = ResumeThread(self.handle.as_raw_handle() as winnt::HANDLE);
            if ret == u32::max_value() {
                Err(Error::last_os_error())
            } else {
                Ok(ret)
            }
        }
    }

    /// Terminates the thread.
    ///
    /// The handle must have the `THREAD_TERMINATE` access right.
    pub fn terminate(&mut self, exit_code: u32) -> WinResult {
        unsafe {
            let ret = TerminateThread(self.handle.as_raw_handle() as winnt::HANDLE, exit_code);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Returns the thread's ideal processor.
    pub fn ideal_processor(&self) -> WinResult<u32> {
        unsafe {
            let mut ideal: PROCESSOR_NUMBER = mem::zeroed();
            let ret =
                GetThreadIdealProcessorEx(self.handle.as_raw_handle() as winnt::HANDLE, &mut ideal);
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
            let ret = SetThreadIdealProcessor(
                self.handle.as_raw_handle() as winnt::HANDLE,
                processor as DWORD,
            );
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
            let affinity = SetThreadAffinityMask(
                self.handle.as_raw_handle() as winnt::HANDLE,
                DWORD_PTR::max_value(),
            );
            if affinity == 0 {
                Err(Error::last_os_error())
            } else {
                let ret =
                    SetThreadAffinityMask(self.handle.as_raw_handle() as winnt::HANDLE, affinity);
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
            let ret = SetThreadAffinityMask(
                self.handle.as_raw_handle() as winnt::HANDLE,
                mask as DWORD_PTR,
            );
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
    fn as_raw_handle(&self) -> RawHandle {
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
    unsafe fn from_raw_handle(handle: RawHandle) -> Thread {
        Thread {
            handle: Handle::new(handle as winnt::HANDLE),
        }
    }
}

impl IntoRawHandle for Thread {
    fn into_raw_handle(self) -> RawHandle {
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
                let ret = Thread32Next(self.snapshot.as_raw_handle() as winnt::HANDLE, &mut entry);
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
                let ret = Thread32Next(self.snapshot.as_raw_handle() as winnt::HANDLE, &mut entry);
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

/// A thread scheduling priority level.
///
/// See [Scheduling Priorities](https://docs.microsoft.com/en-us/windows/desktop/procthread/scheduling-priorities)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum PriorityLevel {
    Idle,
    Lowest,
    BelowNormal,
    Normal,
    AboveNormal,
    Highest,
    TimeCritical,
}

impl PriorityLevel {
    fn from_code(code: DWORD) -> PriorityLevel {
        match code {
            THREAD_PRIORITY_IDLE => PriorityLevel::Idle,
            THREAD_PRIORITY_LOWEST => PriorityLevel::Lowest,
            THREAD_PRIORITY_BELOW_NORMAL => PriorityLevel::BelowNormal,
            THREAD_PRIORITY_NORMAL => PriorityLevel::Normal,
            THREAD_PRIORITY_ABOVE_NORMAL => PriorityLevel::AboveNormal,
            THREAD_PRIORITY_HIGHEST => PriorityLevel::Highest,
            THREAD_PRIORITY_TIME_CRITICAL => PriorityLevel::TimeCritical,
            _ => panic!("Unexpected priority code: {}", code),
        }
    }

    fn as_code(&self) -> DWORD {
        match self {
            PriorityLevel::Idle => THREAD_PRIORITY_IDLE,
            PriorityLevel::Lowest => THREAD_PRIORITY_LOWEST,
            PriorityLevel::BelowNormal => THREAD_PRIORITY_BELOW_NORMAL,
            PriorityLevel::Normal => THREAD_PRIORITY_NORMAL,
            PriorityLevel::AboveNormal => THREAD_PRIORITY_ABOVE_NORMAL,
            PriorityLevel::Highest => THREAD_PRIORITY_HIGHEST,
            PriorityLevel::TimeCritical => THREAD_PRIORITY_TIME_CRITICAL,
        }
    }
}

impl Default for PriorityLevel {
    fn default() -> PriorityLevel {
        PriorityLevel::Normal
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
