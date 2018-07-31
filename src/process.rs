use std::{
    ffi::{CString, OsStr, OsString},
    mem,
    ops::Deref,
    os::windows::{
        io::{AsRawHandle, FromRawHandle, IntoRawHandle},
        prelude::*,
    },
    path::PathBuf,
};

use widestring::WideCString;
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::{ULONG64, DWORD_PTR},
        minwindef::{DWORD, HMODULE, MAX_PATH},
    },
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        libloaderapi::{GetModuleHandleW, GetProcAddress},
        processthreadsapi::{
            GetCurrentProcess,
            GetExitCodeProcess,
            GetProcessId,
            GetThreadId,
            GetThreadIdealProcessorEx,
            OpenProcess,
            OpenThread,
            SetThreadIdealProcessor,
        },
        psapi::{
            EnumProcessModulesEx,
            GetModuleBaseNameW,
            GetModuleFileNameExW,
            GetModuleInformation,
            LIST_MODULES_ALL,
            MODULEINFO,
        },
        realtimeapiset::QueryThreadCycleTime,
        tlhelp32::{
            CreateToolhelp32Snapshot,
            MODULEENTRY32W,
            Module32NextW,
            PROCESSENTRY32,
            Process32Next,
            TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32,
            TH32CS_SNAPPROCESS,
            TH32CS_SNAPTHREAD,
            THREADENTRY32,
            Thread32Next,
        },
        winbase::{
            GetProcessAffinityMask,
            QueryFullProcessImageNameW,
            SetProcessAffinityMask,
            SetThreadAffinityMask,
        },
        winnt::{self, PROCESSOR_NUMBER, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, WCHAR},
    },
};

use Error;
use Handle;
use WinResult;

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
        unsafe { Process::from_handle(Handle::from_raw_handle(GetCurrentProcess())) }
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
                }.filter_map(Result::ok))
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
                }.filter_map(Result::ok))
            }
        }
    }

    /// Returns the process's id.
    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.handle.as_raw_handle()) }
    }

    /// Returns true if the process is running.
    pub fn is_running(&self) -> bool {
        unsafe {
            let mut status = 0;
            GetExitCodeProcess(self.handle.as_raw_handle(), &mut status);
            status == 259
        }
    }

    /// Returns the path of the executable of the process.
    pub fn path(&self) -> WinResult<PathBuf> {
        unsafe {
            let mut size = MAX_PATH as u32;
            let mut buffer: [WCHAR; MAX_PATH] = mem::zeroed();
            let ret = QueryFullProcessImageNameW(
                self.handle.as_raw_handle(),
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

    /// Returns the affinity mask of the process.
    pub fn affinity_mask(&self) -> WinResult<usize> {
        unsafe {
            let mut process_mask: DWORD_PTR = 0;
            let mut system_mask: DWORD_PTR = 0;
            let ret = GetProcessAffinityMask(
                self.handle.as_raw_handle(),
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

    /// Sets the affinity mask of the thread. On success, returns the previous affinity mask.
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
    pub fn set_affinity_mask(&mut self, mask: u32) -> WinResult<()> {
        unsafe {
            let ret = SetProcessAffinityMask(self.handle.as_raw_handle(), mask);
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
    //    pub fn set_affinity(&mut self, processor: u8) -> WinResult<()> {
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
                }.filter_map(Result::ok))
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
            let name = WideCString::from_str(name).map_err(|e| Error::NulErrorW {
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
                        self.as_raw_handle(),
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
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
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
    fn as_raw_handle(&self) -> winnt::HANDLE {
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
    unsafe fn from_raw_handle(handle: winnt::HANDLE) -> Process {
        Process {
            handle: Handle::new(handle),
        }
    }
}

impl IntoRawHandle for Process {
    fn into_raw_handle(self) -> winnt::HANDLE {
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
            let ret = Process32Next(self.snapshot.as_raw_handle(), &mut entry);
            //            if ret == 0 || Error::last().code() == 18 {
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
            let ret = SetThreadAffinityMask(self.handle.as_raw_handle(), DWORD_PTR::max_value());
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                let ret = SetThreadAffinityMask(self.handle.as_raw_handle(), ret);
                if ret == 0 {
                    Err(Error::last_os_error())
                } else {
                    Ok(ret)
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
struct ThreadIter<'a> {
    process: &'a Process,
    snapshot: Handle,
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
struct ThreadIdIter<'a> {
    process: &'a Process,
    snapshot: Handle,
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

/// A handle to a process's loaded module.
#[derive(Debug)]
pub struct Module<'a> {
    handle: HMODULE,
    process: &'a Process,
}

impl<'a> Module<'a> {
    /// Returns the inner HMODULE handle (address) of the loaded module.
    pub fn handle(&self) -> HMODULE {
        self.handle
    }

    /// Returns the base (file) name of the module.
    pub fn name(&self) -> WinResult<String> {
        unsafe {
            let mut buffer: [WCHAR; MAX_PATH] = mem::zeroed();
            let ret = GetModuleBaseNameW(
                self.process.as_raw_handle(),
                self.handle,
                buffer.as_mut_ptr(),
                MAX_PATH as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(OsString::from_wide(&buffer[0..ret as usize])
                    .to_string_lossy()
                    .into_owned())
            }
        }
    }

    /// Returns the fully qualified path to the file that contains the module.
    pub fn path(&self) -> WinResult<PathBuf> {
        unsafe {
            let mut buffer: [WCHAR; MAX_PATH] = mem::zeroed();
            let ret = GetModuleFileNameExW(
                self.process.as_raw_handle(),
                self.handle,
                buffer.as_mut_ptr(),
                MAX_PATH as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(OsString::from_wide(&buffer[0..ret as usize]).into())
            }
        }
    }

    /// Returns a struct containing the address, size, and entry point of the module.
    pub fn info(&self) -> WinResult<ModuleInfo> {
        unsafe {
            let mut c_info: MODULEINFO = mem::zeroed();
            let ret = GetModuleInformation(
                self.process.as_raw_handle(),
                self.handle,
                &mut c_info,
                mem::size_of::<MODULEINFO>() as _,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(c_info.into())
            }
        }
    }

    /// Returns a void pointer to the function in the module with the specified name.
    pub fn proc_address(&self, proc_name: &str) -> WinResult<*mut c_void> {
        unsafe {
            let ret = GetProcAddress(self.handle, CString::new(proc_name)?.as_ptr() as _);
            if ret.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(ret as *mut c_void)
            }
        }
    }
}

/// Holds the address, size, and entry point of a loaded module.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Base address of the module (equivalent to its HMODULE).
    pub address: *mut c_void,
    /// Size of the module in bytes.
    pub size: usize,
    /// Entry point of the module. While this is not the address of the `DllMain` function,
    /// it should be close enough for most purposes.
    pub entry_point: *mut c_void,
}

impl From<MODULEINFO> for ModuleInfo {
    fn from(mi: MODULEINFO) -> ModuleInfo {
        ModuleInfo {
            address: mi.lpBaseOfDll,
            size: mi.SizeOfImage as usize,
            entry_point: mi.EntryPoint,
        }
    }
}

/// Holds data related to a module of a running process.
///
/// Maps almost directly to a Windows [MODULEENTRY32W][MODULEENTRY32W].
///
/// [MODULEENTRY32W]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684225(v=vs.85).aspx
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// This member is no longer used, and is always set to one.
    pub id: u32,
    /// The module's basename.
    pub name: String,
    /// The path to the module's file.
    pub path: PathBuf,
    /// A handle to the module in the context of the owning process.
    pub hmodule: HMODULE,
    /// The identifier of the process in which the module is loaded.
    pub process_id: u32,
    /// The load count of the module, which is not generally meaningful,
    /// and usually equal to `0xffff`.
    pub global_load_count: u32,
    /// The load count of the module (same as GlblcntUsage), which is not
    /// generally meaningful, and usually equal to `0xffff`.
    pub proc_load_count: u32,
    /// The base address of the module in the context of the owning process.
    pub mod_base_addr: *mut u8,
    /// The size of the module, in bytes.
    pub mod_base_size: u32,
}

impl From<MODULEENTRY32W> for ModuleEntry {
    fn from(me: MODULEENTRY32W) -> ModuleEntry {
        let name_end = me
            .szModule
            .iter()
            .position(|&b| b == 0)
            .unwrap_or_else(|| me.szModule.len());
        let name = OsString::from_wide(&me.szModule[..name_end])
            .to_string_lossy()
            .into_owned();

        let path_end = me
            .szExePath
            .iter()
            .position(|&b| b == 0)
            .unwrap_or_else(|| me.szModule.len());
        let path = OsString::from_wide(&me.szExePath[..path_end]).into();

        ModuleEntry {
            id: me.th32ModuleID,
            name,
            path,
            hmodule: me.hModule,
            process_id: me.th32ProcessID,
            global_load_count: me.GlblcntUsage,
            proc_load_count: me.ProccntUsage,
            mod_base_addr: me.modBaseAddr,
            mod_base_size: me.modBaseSize,
        }
    }
}

#[derive(Debug)]
struct ModuleEntryIter<'a> {
    process: &'a Process,
    snapshot: Handle,
}

impl<'a> Iterator for ModuleEntryIter<'a> {
    type Item = ModuleEntry;

    fn next(&mut self) -> Option<ModuleEntry> {
        unsafe {
            let mut entry: MODULEENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<MODULEENTRY32W>() as DWORD;
            let ret = Module32NextW(self.snapshot.as_raw_handle(), &mut entry);
            if ret == 0 {
                None
            } else {
                Some(entry.into())
            }
        }
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
//
//    #[test]
//    fn enumerates_threads() {
//        let process = Process::all().unwrap().next().unwrap();
//        let threads: Vec<_> = process.threads().unwrap().collect();
//        assert_eq!(threads.is_empty(), false);
//        println!("{:?}", threads);
//    }
//
//    #[test]
//    fn lists_modules() {
//        let process = Process::all().unwrap().next().unwrap();
//        let entries: Vec<_> = process.module_entries().unwrap().collect();
//        assert_eq!(entries.is_empty(), false);
//        println!("{:?}", entries);
//    }
//
//    #[test]
//    fn enumerates_module_entries() {
//        let process = Process::all().unwrap().next().unwrap();
//        let modules: Vec<_> = process.module_list().unwrap();
//        assert_eq!(modules.is_empty(), false);
//        println!("{:?}", modules);
//    }
//
//    #[test]
//    fn retrieves_module() {
//        let process = Process::all().unwrap().next().unwrap();
//        let module = process.module("kernel32").unwrap();
//        assert_eq!(module.name().unwrap().to_lowercase(), "kernel32.dll");
//    }
//
//    #[test]
//    fn proc_address() {
//        use winapi::um::winnt::HANDLE;
//        type GetProcessIdFn = extern "system" fn(HANDLE) -> DWORD;
//
//        let process = Process::all().unwrap().next().unwrap();
//        let k32 = process.module("kernel32").unwrap();
//
//        unsafe {
//            let get_process_id: GetProcessIdFn =
//                mem::transmute(k32.proc_address("GetProcessId").unwrap());
//            assert_eq!(get_process_id(process.as_raw_handle()), process.id());
//        }
//    }
//}
