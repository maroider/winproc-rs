use self::{
    module::ModuleEntryIter,
    thread::{ThreadIdIter, ThreadIter},
};
pub use self::{
    module::{Module, ModuleEntry, ModuleInfo},
    thread::{PriorityLevel, Thread},
};
use crate::{Error, Handle, WinResult};
use bitflags::bitflags;
use std::{
    ffi::{OsStr, OsString},
    mem,
    ops::Deref,
    os::windows::{
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle},
        prelude::*,
    },
    path::PathBuf,
};
use widestring::WideCString;
use winapi::{
    shared::{
        basetsd::DWORD_PTR,
        minwindef::{DWORD, HMODULE, MAX_PATH},
    },
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        libloaderapi::GetModuleHandleW,
        processthreadsapi::{
            GetCurrentProcess,
            GetExitCodeProcess,
            GetPriorityClass,
            GetProcessId,
            OpenProcess,
            SetPriorityClass,
            TerminateProcess,
        },
        psapi::{EnumProcessModulesEx, LIST_MODULES_ALL},
        tlhelp32::{
            CreateToolhelp32Snapshot,
            Process32Next,
            PROCESSENTRY32,
            TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32,
            TH32CS_SNAPPROCESS,
            TH32CS_SNAPTHREAD,
        },
        winbase::{
            GetProcessAffinityMask,
            QueryFullProcessImageNameW,
            SetProcessAffinityMask,
            ABOVE_NORMAL_PRIORITY_CLASS,
            BELOW_NORMAL_PRIORITY_CLASS,
            HIGH_PRIORITY_CLASS,
            IDLE_PRIORITY_CLASS,
            NORMAL_PRIORITY_CLASS,
            PROCESS_MODE_BACKGROUND_BEGIN,
            PROCESS_MODE_BACKGROUND_END,
            REALTIME_PRIORITY_CLASS,
        },
        winnt::{self, PROCESS_ALL_ACCESS, WCHAR},
    },
};

mod module;
mod thread;

/// A handle to a running process.
#[derive(Debug)]
pub struct Process {
    handle: Handle,
}

impl Process {
    /// Creates a process handle from a PID. Requests all access permissions.
    pub fn from_id(id: u32) -> WinResult<Process> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, id);
            if handle.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(Process {
                    handle: Handle::new(handle),
                })
            }
        }
    }

    /// Creates a process handle from a PID. Requests the specified access permissions.
    pub fn from_id_with_access(id: u32, access: Access) -> WinResult<Process> {
        unsafe {
            let handle = OpenProcess(access.bits, 0, id);
            if handle.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(Process {
                    handle: Handle::new(handle),
                })
            }
        }
    }

    /// Creates a process handle from a name. Requests all access.
    pub fn from_name(name: &str) -> WinResult<Process> {
        Process::all()?
            .find(|p| p.name().map(|n| n == name).unwrap_or(false))
            .ok_or(Error::NoProcess(name.to_string()))
    }

    /// Creates a process handle from a name.
    pub fn from_name_with_access(name: &str, access: Access) -> WinResult<Process> {
        Process::all_with_access(access)?
            .find(|p| p.name().map(|n| n == name).unwrap_or(false))
            .ok_or(Error::NoProcess(name.to_string()))
    }

    /// Creates a process handle from a handle.
    pub fn from_handle(handle: Handle) -> Process {
        Process { handle }
    }

    /// Returns a handle to the current process.
    pub fn current() -> Process {
        unsafe { Process::from_handle(Handle::from_raw_handle(GetCurrentProcess() as RawHandle)) }
    }

    /// Returns a reference to the inner handle.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Enumerates all running processes. Requests all access.
    pub fn all() -> WinResult<impl Iterator<Item = Process>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                Err(Error::last_os_error())
            } else {
                Ok(ProcessIter {
                    snapshot: Handle::new(snap),
                    access: Access::PROCESS_ALL_ACCESS,
                }
                .filter_map(Result::ok))
            }
        }
    }

    /// Enumerates all running processes.
    pub fn all_with_access(access: Access) -> WinResult<impl Iterator<Item = Process>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                Err(Error::last_os_error())
            } else {
                Ok(ProcessIter {
                    snapshot: Handle::new(snap),
                    access,
                }
                .filter_map(Result::ok))
            }
        }
    }

    /// Returns the process's id.
    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.handle.as_raw_handle() as winnt::HANDLE) }
    }

    /// Returns true if the process is running.
    pub fn is_running(&self) -> bool {
        unsafe {
            let mut status = 0;
            GetExitCodeProcess(self.handle.as_raw_handle() as winnt::HANDLE, &mut status);
            status == 259
        }
    }

    /// Returns the path of the executable of the process.
    pub fn path(&self) -> WinResult<PathBuf> {
        unsafe {
            let mut size = MAX_PATH as u32;
            let mut buffer: [WCHAR; MAX_PATH] = mem::zeroed();
            let ret = QueryFullProcessImageNameW(
                self.handle.as_raw_handle() as winnt::HANDLE,
                0,
                buffer.as_mut_ptr(),
                &mut size,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(OsString::from_wide(&buffer[0..size as usize]).into())
            }
        }
    }

    /// Returns the unqualified name of the executable of the process.
    pub fn name(&self) -> WinResult<String> {
        Ok(self
            .path()?
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned())
    }

    /// Returns the priority class of the process.
    ///
    /// The handle must have the `PROCESS_QUERY_INFORMATION` or `PROCESS_QUERY_LIMITED_INFORMATION`
    /// access right.
    pub fn priority(&self) -> WinResult<PriorityClass> {
        unsafe {
            let ret = GetPriorityClass(self.handle.as_raw_handle() as winnt::HANDLE);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(PriorityClass::from_code(ret))
            }
        }
    }

    /// Sets the priority class of the process.
    ///
    /// The handle must have the `PROCESS_SET_INFORMATION` access right.
    pub fn set_priority(&mut self, priority: PriorityClass) -> WinResult {
        unsafe {
            let ret = SetPriorityClass(
                self.handle.as_raw_handle() as winnt::HANDLE,
                priority.as_code(),
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
    /// **This can be initiated only if the handle refers to the current process.**
    ///
    /// The system lowers the resource scheduling priorities of the process (and its threads) so
    /// that it can perform background work without significantly affecting activity in
    /// the foreground.
    ///
    /// The function fails if the process is already in background processing mode.
    ///
    /// The handle must have the `PROCESS_SET_INFORMATION` access right.
    pub fn start_background_mode(&mut self) -> WinResult {
        unsafe {
            let ret = SetPriorityClass(
                self.handle.as_raw_handle() as winnt::HANDLE,
                PROCESS_MODE_BACKGROUND_BEGIN,
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
    /// **This can be initiated only if the handle refers to the current process.**
    ///
    /// The system restores the resource scheduling priorities of the process (and its threads) as
    /// they were before the process entered background processing mode.
    ///
    /// The function fails if the process is not in background processing mode.
    ///
    /// The handle must have the `PROCESS_SET_INFORMATION` access right.
    pub fn end_background_mode(&mut self) -> WinResult {
        unsafe {
            let ret = SetPriorityClass(
                self.handle.as_raw_handle() as winnt::HANDLE,
                PROCESS_MODE_BACKGROUND_END,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Terminates the process.
    ///
    /// The handle must have the `PROCESS_TERMINATE` access right.
    pub fn terminate(&mut self, exit_code: u32) -> WinResult {
        unsafe {
            let ret = TerminateProcess(self.handle.as_raw_handle() as winnt::HANDLE, exit_code);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Returns the affinity mask of the process.
    pub fn affinity_mask(&self) -> WinResult<usize> {
        unsafe {
            let mut process_mask: DWORD_PTR = 0;
            let mut system_mask: DWORD_PTR = 0;
            let ret = GetProcessAffinityMask(
                self.handle.as_raw_handle() as winnt::HANDLE,
                &mut process_mask,
                &mut system_mask,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(process_mask as usize)
            }
        }
    }

    /// Sets the affinity mask of the process.
    ///
    /// A process affinity mask is a bit vector in which each bit represents a logical processor
    /// that a process is allowed to run on.
    ///
    /// Setting an affinity mask for a process or thread can result in threads receiving less
    /// processor time, as the system is restricted from running the threads on certain processors.
    /// In most cases, it is better to let the system select an available processor.
    ///
    /// If the new process affinity mask does not specify the processor that is currently running
    /// the process, the process is rescheduled on one of the allowable processors.
    pub fn set_affinity_mask(&mut self, mask: u32) -> WinResult {
        unsafe {
            let ret = SetProcessAffinityMask(self.handle.as_raw_handle() as winnt::HANDLE, mask);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    //    /// Sets the affinity of the process to the single specified processor.
    //    ///
    //    /// If the processor index equals or exceeds the width of [`DWORD`], the mask is not changed.
    //    pub fn set_affinity(&mut self, processor: u8) -> WinResult {
    //        if (processor as usize) < mem::size_of::<u32>() * 8 {
    //            self.set_affinity_mask(1 << processor as u32)
    //        } else {
    //            Ok(())
    //        }
    //    }

    /// Returns an iterator over the threads of the process.
    pub fn threads<'a>(&'a self) -> WinResult<impl Iterator<Item = Thread> + 'a> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                Err(Error::last_os_error())
            } else {
                Ok(ThreadIter {
                    process: &self,
                    snapshot: Handle::new(snap),
                }
                .filter_map(Result::ok))
            }
        }
    }

    /// Returns an iterator over the ids of threads of the process.
    pub fn thread_ids<'a>(&'a self) -> WinResult<impl Iterator<Item = u32> + 'a> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                Err(Error::last_os_error())
            } else {
                Ok(ThreadIdIter {
                    process: &self,
                    snapshot: Handle::new(snap),
                })
            }
        }
    }

    /// Returns the loaded module with the specified name/path.
    pub fn module<N: AsRef<OsStr>>(&self, name: N) -> WinResult<Module> {
        unsafe {
            let name = WideCString::from_os_str(name).map_err(|e| Error::NulErrorW {
                pos: e.nul_position(),
                data: e.into_vec(),
            })?;
            let ret = GetModuleHandleW(name.as_ptr());
            if ret.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(Module {
                    handle: ret,
                    process: self,
                })
            }
        }
    }

    /// Returns a list of the modules of the process.
    pub fn module_list(&self) -> WinResult<Vec<Module>> {
        unsafe {
            let mut mod_handles = Vec::new();
            let mut reserved = 0;
            let mut needed = 0;

            {
                let enum_mods = |mod_handles: &mut [HMODULE], needed| {
                    let res = EnumProcessModulesEx(
                        self.as_raw_handle() as winnt::HANDLE,
                        mod_handles.as_mut_ptr(),
                        mem::size_of_val(&mod_handles[..]) as _,
                        needed,
                        LIST_MODULES_ALL,
                    );
                    if res == 0 {
                        Err(Error::last_os_error())
                    } else {
                        Ok(())
                    }
                };

                loop {
                    enum_mods(&mut mod_handles, &mut needed)?;
                    if needed <= reserved {
                        break;
                    }
                    reserved = needed;
                    mod_handles.resize(needed as usize, mem::zeroed());
                }
            }

            let modules = mod_handles[..needed as usize / mem::size_of::<HMODULE>()]
                .iter()
                .map(|&handle| Module {
                    handle,
                    process: self,
                })
                .collect();
            Ok(modules)
        }
    }

    /// Returns an iterator over the modules of the process.
    pub fn module_entries<'a>(&'a self) -> WinResult<impl Iterator<Item = ModuleEntry> + 'a> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.id());
            if snap == INVALID_HANDLE_VALUE {
                Err(Error::last_os_error())
            } else {
                Ok(ModuleEntryIter {
                    process: &self,
                    snapshot: Handle::new(snap),
                })
            }
        }
    }
}

impl AsRawHandle for Process {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

impl Deref for Process {
    type Target = winnt::HANDLE;

    fn deref(&self) -> &winnt::HANDLE {
        &*self.handle
    }
}

impl FromRawHandle for Process {
    unsafe fn from_raw_handle(handle: RawHandle) -> Process {
        Process {
            handle: Handle::new(handle as winnt::HANDLE),
        }
    }
}

impl IntoRawHandle for Process {
    fn into_raw_handle(self) -> RawHandle {
        self.handle.into_raw_handle()
    }
}

#[derive(Debug)]
struct ProcessIter {
    snapshot: Handle,
    access: Access,
}

impl Iterator for ProcessIter {
    type Item = WinResult<Process>;

    fn next(&mut self) -> Option<WinResult<Process>> {
        unsafe {
            let mut entry: PROCESSENTRY32 = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;
            let ret = Process32Next(self.snapshot.as_raw_handle() as winnt::HANDLE, &mut entry);
            if ret == 0 {
                None
            } else {
                Some(Process::from_id_with_access(
                    entry.th32ProcessID,
                    self.access,
                ))
            }
        }
    }
}

bitflags! {
    /// Windows process-related access permission flags.
    pub struct Access: u32 {
        /// Required to delete the object.
        const DELETE = winnt::DELETE;
        /// Required to read information in the security descriptor for the object, not including
        /// the information in the SACL. To read or write the SACL, you must request the
        /// `ACCESS_SYSTEM_SECURITY` access right. For more information, see [SACL Access Right](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379321\(v=vs.85\).aspx).
        const READ_CONTROL = winnt::READ_CONTROL;
        /// Required to modify the DACL in the security descriptor for the object.
        const WRITE_DAC = winnt::WRITE_DAC;
        /// Required to change the owner in the security descriptor for the object.
        const WRITE_OWNER = winnt::WRITE_OWNER;
        /// The right to use the object for synchronization.
        /// This enables a thread to wait until the object is in the signaled state.
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        /// Union of `DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER`.
        const STANDARD_RIGHTS_REQUIRED = winnt::STANDARD_RIGHTS_REQUIRED;
        /// Required to terminate a process.
        const PROCESS_TERMINATE = winnt::PROCESS_TERMINATE;
        ///	Required to create a thread.
        const PROCESS_CREATE_THREAD = winnt::PROCESS_CREATE_THREAD;
        const PROCESS_SET_SESSIONID = winnt::PROCESS_SET_SESSIONID;
        /// Required to perform an operation on the address space of a process.
        const PROCESS_VM_OPERATION = winnt::PROCESS_VM_OPERATION;
        /// Required to read memory in a process.
        const PROCESS_VM_READ = winnt::PROCESS_VM_READ;
        /// Required to write to memory in a process.
        const PROCESS_VM_WRITE = winnt::PROCESS_VM_WRITE;
        /// Required to duplicate a handle.
        const PROCESS_DUP_HANDLE = winnt::PROCESS_DUP_HANDLE;
        /// Required to create a process.
        const PROCESS_CREATE_PROCESS = winnt::PROCESS_CREATE_PROCESS;
        /// Required to set memory limits.
        const PROCESS_SET_QUOTA = winnt::PROCESS_SET_QUOTA;
        /// Required to set certain information about a process, such as its priority class.
        const PROCESS_SET_INFORMATION = winnt::PROCESS_SET_INFORMATION;
        /// Required to retrieve certain information about a process, such as its token,
        /// exit code, and priority class.
        const PROCESS_QUERY_INFORMATION = winnt::PROCESS_QUERY_INFORMATION;
        /// Required to suspend or resume a process.
        const PROCESS_SUSPEND_RESUME = winnt::PROCESS_SUSPEND_RESUME;
        /// Required to retrieve certain information about a process
        /// (exit code, priority class,job status, path).
        ///
        /// A handle that has the `PROCESS_QUERY_INFORMATION` access right is
        /// automatically granted `PROCESS_QUERY_LIMITED_INFORMATION`.
        const PROCESS_QUERY_LIMITED_INFORMATION = winnt::PROCESS_QUERY_LIMITED_INFORMATION;
        const PROCESS_SET_LIMITED_INFORMATION = winnt::PROCESS_SET_LIMITED_INFORMATION;
        /// All possible access rights for a process object.
        const PROCESS_ALL_ACCESS = Self::STANDARD_RIGHTS_REQUIRED.bits | Self::SYNCHRONIZE.bits | 0xffff;
    }
}

impl Default for Access {
    /// Returns `Access::PROCESS_ALL_ACCESS`.
    fn default() -> Access {
        Access::PROCESS_ALL_ACCESS
    }
}

/// A process scheduling priority class.
///
/// See [Scheduling Priorities](https://docs.microsoft.com/en-us/windows/desktop/procthread/scheduling-priorities)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum PriorityClass {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
}

impl PriorityClass {
    fn from_code(code: DWORD) -> PriorityClass {
        match code {
            IDLE_PRIORITY_CLASS => PriorityClass::Idle,
            BELOW_NORMAL_PRIORITY_CLASS => PriorityClass::BelowNormal,
            NORMAL_PRIORITY_CLASS => PriorityClass::Normal,
            ABOVE_NORMAL_PRIORITY_CLASS => PriorityClass::AboveNormal,
            HIGH_PRIORITY_CLASS => PriorityClass::High,
            REALTIME_PRIORITY_CLASS => PriorityClass::Realtime,
            _ => panic!("Unexpected priority code: {}", code),
        }
    }

    fn as_code(&self) -> DWORD {
        match self {
            PriorityClass::Idle => IDLE_PRIORITY_CLASS,
            PriorityClass::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            PriorityClass::Normal => NORMAL_PRIORITY_CLASS,
            PriorityClass::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
            PriorityClass::High => HIGH_PRIORITY_CLASS,
            PriorityClass::Realtime => REALTIME_PRIORITY_CLASS,
        }
    }
}

impl Default for PriorityClass {
    fn default() -> PriorityClass {
        PriorityClass::Normal
    }
}

//mod tests {
//    #[allow(unused_imports)]
//    use super::*;
//
//    #[test]
//    fn enumerates_processes() {
//        let procs: Vec<_> = Process::all().unwrap().collect();
//        assert_eq!(procs.is_empty(), false);
//        println!("{:?}", procs);
//    }
//
//    #[test]
//    fn accesses_process_names() {
//        let names: Vec<_> = Process::all()
//            .unwrap()
//            .filter_map(|p| p.name().ok())
//            .collect();
//        assert_eq!(names.is_empty(), false);
//        println!("{:?}", names);
//    }
//}
