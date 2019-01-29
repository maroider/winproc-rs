use std::{
    ffi::{CString, OsString},
    mem,
    os::windows::{io::AsRawHandle, prelude::*},
    path::PathBuf,
};
use winapi::{
    ctypes::c_void,
    shared::minwindef::{DWORD, HMODULE, MAX_PATH},
    um::{
        libloaderapi::GetProcAddress,
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW, GetModuleInformation, MODULEINFO},
        tlhelp32::{Module32NextW, MODULEENTRY32W},
        winnt::{self, WCHAR},
    },
};
use Error;
use Handle;
use Process;
use WinResult;

/// A handle to a process's loaded module.
#[derive(Debug)]
pub struct Module<'a> {
    pub(crate) handle: HMODULE,
    pub(crate) process: &'a Process,
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
                self.process.as_raw_handle() as winnt::HANDLE,
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
                self.process.as_raw_handle() as winnt::HANDLE,
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
                self.process.as_raw_handle() as winnt::HANDLE,
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
pub struct ModuleEntryIter<'a> {
    pub(crate) process: &'a Process,
    pub(crate) snapshot: Handle,
}

impl<'a> Iterator for ModuleEntryIter<'a> {
    type Item = ModuleEntry;

    fn next(&mut self) -> Option<ModuleEntry> {
        unsafe {
            let mut entry: MODULEENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<MODULEENTRY32W>() as DWORD;
            let ret = Module32NextW(self.snapshot.as_raw_handle() as winnt::HANDLE, &mut entry);
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
//}
