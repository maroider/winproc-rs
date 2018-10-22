//! Small wrapper over some process-related Windows APIs.

#![cfg(windows)]

#[macro_use]
extern crate bitflags;
extern crate winapi;
#[macro_use]
extern crate failure;
extern crate widestring;

pub mod errors;
mod handle;
mod process;

use std::mem;

use winapi::{
    ctypes::c_void,
    shared::minwindef::WORD,
    um::{
        sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO},
        winnt::{
            PROCESSOR_ARCHITECTURE_ALPHA,
            PROCESSOR_ARCHITECTURE_ALPHA64,
            PROCESSOR_ARCHITECTURE_AMD64,
            PROCESSOR_ARCHITECTURE_ARM,
            PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64,
            PROCESSOR_ARCHITECTURE_ARM64,
            PROCESSOR_ARCHITECTURE_IA32_ON_ARM64,
            PROCESSOR_ARCHITECTURE_IA32_ON_WIN64,
            PROCESSOR_ARCHITECTURE_IA64,
            PROCESSOR_ARCHITECTURE_INTEL,
            PROCESSOR_ARCHITECTURE_MIPS,
            PROCESSOR_ARCHITECTURE_MSIL,
            PROCESSOR_ARCHITECTURE_NEUTRAL,
            PROCESSOR_ARCHITECTURE_PPC,
            PROCESSOR_ARCHITECTURE_SHX,
        },
    },
};

pub use self::{
    errors::{Error, WinResult},
    handle::Handle,
    process::{
        Access,
        Module,
        ModuleEntry,
        ModuleInfo,
        PriorityClass,
        PriorityLevel,
        Process,
        Thread,
    },
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ProcessorArchitecture {
    /// x64 (AMD or Intel)
    AMD64,
    Alpha,
    Alpha64,
    ARM,
    ARM64,
    /// Intel Itanium-based
    IA64,
    /// x86
    Intel,
    PPC,
    SHX,
    MIPS,
    MSIL,
    Neutral,
    ARM32OnWin64,
    IA32OnWin64,
    IA32OnARM64,
    Unknown,
}

impl From<WORD> for ProcessorArchitecture {
    fn from(processor_architecture: WORD) -> ProcessorArchitecture {
        match processor_architecture {
            PROCESSOR_ARCHITECTURE_AMD64 => ProcessorArchitecture::AMD64,
            PROCESSOR_ARCHITECTURE_ARM => ProcessorArchitecture::ARM,
            PROCESSOR_ARCHITECTURE_ARM64 => ProcessorArchitecture::ARM64,
            PROCESSOR_ARCHITECTURE_ALPHA64 => ProcessorArchitecture::Alpha64,
            PROCESSOR_ARCHITECTURE_PPC => ProcessorArchitecture::PPC,
            PROCESSOR_ARCHITECTURE_SHX => ProcessorArchitecture::SHX,
            PROCESSOR_ARCHITECTURE_IA64 => ProcessorArchitecture::IA64,
            PROCESSOR_ARCHITECTURE_MIPS => ProcessorArchitecture::MIPS,
            PROCESSOR_ARCHITECTURE_MSIL => ProcessorArchitecture::MSIL,
            PROCESSOR_ARCHITECTURE_ALPHA => ProcessorArchitecture::Alpha,
            PROCESSOR_ARCHITECTURE_INTEL => ProcessorArchitecture::Intel,
            PROCESSOR_ARCHITECTURE_NEUTRAL => ProcessorArchitecture::Neutral,
            PROCESSOR_ARCHITECTURE_IA32_ON_ARM64 => ProcessorArchitecture::IA32OnARM64,
            PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 => ProcessorArchitecture::IA32OnWin64,
            PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64 => ProcessorArchitecture::ARM32OnWin64,
            _ => ProcessorArchitecture::Unknown,
        }
    }
}

/// Information about the current system.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SystemInfo {
    /// The processor architecture of the installed operating system.
    pub processor_architecture: ProcessorArchitecture,
    /// The page size and the granularity of page protection and commitment.
    /// This is the page size used by the VirtualAlloc function.
    pub page_size: u32,
    /// A pointer to the lowest memory address accessible to applications and
    /// dynamic-link libraries (DLLs).
    pub minimum_application_address: *mut c_void,
    /// A pointer to the highest memory address accessible to applications and DLLs.
    pub maximum_application_address: *mut c_void,
    /// A mask representing the set of processors configured into the system.
    /// Bit 0 is processor 0; bit 31 is processor 31.
    pub active_processor_mask: usize,
    /// The number of logical processors in the current group.
    pub processor_count: u32,
    /// The granularity for the starting address at which virtual memory can be allocated.
    pub allocation_granularity: u32,
    /// The architecture-dependent processor level. It should be used only for display purposes.
    ///
    /// If `processor_architecture` is `Intel`, `processor_level` is defined by the CPU vendor.
    ///
    /// If `processor_architecture` is `IA64`, `processor_level` is set to `1`.
    pub processor_level: u16,
    /// The architecture-dependent processor revision.
    ///
    /// Processor                            | Value
    /// ------------------------------------ | ------------------------------------
    /// Intel Pentium, Cyrix, or NextGen 586 | The high byte is the model and the low byte is the stepping. <br> For example, if the value is xxyy, the model number and stepping can be displayed as follows: <br> Model xx, Stepping yy
    /// Intel 80386 or 80486                 | A value of the form xxyz. <br> If xx is equal to 0xFF, y - 0xA is the model number, and z is the stepping identifier. <br> If xx is not equal to 0xFF, xx + 'A' is the stepping letter and yz is the minor stepping.
    pub processor_revision: u16,
}

unsafe impl Send for SystemInfo {}
unsafe impl Sync for SystemInfo {}

/// Retrieves information about the current system.
pub fn system_info() -> SystemInfo {
    unsafe {
        let mut system_info: SYSTEM_INFO = mem::zeroed();
        GetNativeSystemInfo(&mut system_info);
        system_info.into()
    }
}

impl From<SYSTEM_INFO> for SystemInfo {
    fn from(system_info: SYSTEM_INFO) -> SystemInfo {
        unsafe {
            SystemInfo {
                processor_architecture: system_info.u.s().wProcessorArchitecture.into(),
                page_size: system_info.dwPageSize,
                minimum_application_address: system_info.lpMinimumApplicationAddress,
                maximum_application_address: system_info.lpMaximumApplicationAddress,
                active_processor_mask: system_info.dwActiveProcessorMask,
                processor_count: system_info.dwNumberOfProcessors,
                allocation_granularity: system_info.dwAllocationGranularity,
                processor_level: system_info.wProcessorLevel,
                processor_revision: system_info.wProcessorRevision,
            }
        }
    }
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    #[test]
//    fn retrieve_system_info() {
//        let si = system_info();
//        println!("{:?}", si);
//    }
//}
