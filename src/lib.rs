//! Small wrapper over some process-related Windows APIs.

#![cfg(windows)]

extern crate winapi;
#[macro_use]
extern crate failure;

pub mod errors;
mod handle;
mod process;

pub use self::{
    errors::{Error, WinResult},
    handle::Handle,
    process::{ModuleEntry, Process, Thread},
};
