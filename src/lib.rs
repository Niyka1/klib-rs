#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, improper_ctypes)]
extern crate alloc;
#[cfg(feature = "kernel")]
use alloc::vec::Vec;
#[cfg(feature = "kernel")]
use core::ffi::c_void;
use core::{ptr, slice};
pub use crate::wdm::*;
pub mod wdm;
#[cfg(feature = "kernel")]
pub mod memory;
#[cfg(feature = "kernel")]
pub mod khook;
#[cfg(feature = "kernel")]
pub mod kalloc;
#[cfg(feature = "ntddk")]
pub mod ntddk;
#[cfg(feature = "ntifs")]
pub mod ntifs;



#[inline(always)]
pub fn segment_limit(selector: u16) -> Option<u32> {
    let mut limit;
    let mut ok: u8;

    unsafe {
        core::arch::asm!(
        "lsl {limit:e}, {selector:x}",
        "setz {ok}",
        limit = out(reg) limit,
        selector = in(reg) selector,
        ok = out(reg_byte) ok,
        options(nomem, nostack, preserves_flags),
        );
    }
    if ok != 0 {
        Some(limit)
    } else {
        None
    }
}

pub type NTSTATUS = i32;

// NTSTATUS codes (small)
pub const STATUS_SUCCESS: NTSTATUS                 = 0x00000000;
pub const STATUS_UNSUCCESSFUL: NTSTATUS            = 0xC0000001u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS       = 0xC000000Du32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS    = 0xC0000004u32 as i32;
pub const STATUS_NO_MEMORY: NTSTATUS               = 0xC0000017u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS  = 0xC000009Au32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS   = 0xC0000034u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023u32 as i32;


#[inline(always)]
pub const fn NT_SUCCESS(status: NTSTATUS) -> bool {
    status >= 0
}


pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1b;


#[repr(C)]
#[derive(Copy, Clone)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
    pub Section: PVOID,
    pub MappedBase: PVOID,
    pub ImageBase: PVOID,
    pub ImageSize: ULONG,
    pub Flags: ULONG,
    pub LoadOrderIndex: USHORT,
    pub InitOrderIndex: USHORT,
    pub LoadCount: USHORT,
    pub OffsetToFileName: USHORT,
    pub FullPathName: [UCHAR; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RTL_PROCESS_MODULES {
    pub NumberOfModules: ULONG,
    pub Modules: [RTL_PROCESS_MODULE_INFORMATION; 1],
}


pub const SystemModuleInformation: u32 = 11;
pub const SystemProcessInformation: u32 = 5;
pub const IoReadAccess: i32 = 1;
pub const MmNonCached: i32 = 0;


#[repr(C)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: ULONG,
    pub NumberOfThreads: ULONG,
    pub Reserved1: [u64; 3],
    pub CreateTime: i64,
    pub UserTime: i64,
    pub KernelTime: i64,
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: PVOID,
    pub InheritedFromUniqueProcessId: PVOID,
}



#[repr(C)]
#[derive(Copy, Clone)]
pub union MouseButtons {
    pub Buttons: ULONG,
    pub ButtonFields: ButtonFields,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ButtonFields {
    pub ButtonFlags: USHORT,
    pub ButtonData: USHORT,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MOUSE_INPUT_DATA {
    pub UnitId: USHORT,
    pub Flags: USHORT,
    pub u: MouseButtons,
    pub RawButtons: ULONG,
    pub LastX: LONG,
    pub LastY: LONG,
    pub ExtraInformation: ULONG,
}


pub type PMOUSE_INPUT_DATA = *mut MOUSE_INPUT_DATA;

pub type MouseClassServiceCallbackFn = Option<unsafe extern "system" fn(DeviceObject: PDEVICE_OBJECT, InputDataStart: PMOUSE_INPUT_DATA, InputDataEnd: PMOUSE_INPUT_DATA, InputDataConsumed: PULONG)>;



#[derive(Copy, Clone)]
pub struct MOUSE_OBJECT {
    pub mouse_device: PDEVICE_OBJECT,
    pub service_call_back: MouseClassServiceCallbackFn,
    pub use_mouse: i32,
}



#[cfg(feature = "kernel")]
unsafe extern "C" {
    pub static IoDriverObjectType: *mut *mut u8;
    pub fn PsLookupProcessByProcessId(ProcessId: HANDLE, Process: *mut PEPROCESS) -> wdm::NTSTATUS;
    pub fn ZwQuerySystemInformation(SystemInformationClass: u32, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: *mut ULONG) -> NTSTATUS;
    pub fn RtlSecureZeroMemory(Destination: PVOID, Length: SIZE_T) -> PVOID;
    pub fn RtlFindExportedRoutineByName(image_base: PVOID, routine_name: *const u8) -> PVOID;
    pub fn PsGetProcessPeb(pep: PEPROCESS) -> u64;
    pub fn MmCopyVirtualMemory(FromProcess: PEPROCESS, FromAddress: PVOID, ToProcess: PEPROCESS, ToAddress: PVOID, BufferSize: SIZE_T,
                               PreviousMode: KPROCESSOR_MODE, NumberOfBytesCopied: *mut SIZE_T) -> NTSTATUS;

    pub fn PsGetCurrentProcess() -> PEPROCESS;
    pub fn PsGetProcessSectionBaseAddress(Process: PEPROCESS) -> PVOID;
    pub fn ObReferenceObjectByName(ObjectName: *mut UNICODE_STRING, Attributes: ULONG, PassedAccessState: *mut ACCESS_STATE, DesiredAccess: ACCESS_MASK, ObjectType: *mut u8,
    AccessMode: u8, ParseContext: *mut c_void, Object: *mut *mut c_void) -> NTSTATUS;
    pub fn ZwCurrentProcess() -> HANDLE;
    pub fn IoCreateDriver(DriverName: *mut UNICODE_STRING, InitializationFunction: extern "system" fn(*mut c_void, *mut UNICODE_STRING) -> NTSTATUS) -> NTSTATUS;
}




pub fn modules_from_ptr<'a>(ptr: *const RTL_PROCESS_MODULES) -> &'a [RTL_PROCESS_MODULE_INFORMATION] {
    unsafe {
        if ptr.is_null() {
            &[]
        } else {
            let count = (*ptr).NumberOfModules as usize;
            let first = &(*ptr).Modules as *const RTL_PROCESS_MODULE_INFORMATION;
            slice::from_raw_parts(first, count)
        }
    }
}


pub fn filename_from_info(info: &RTL_PROCESS_MODULE_INFORMATION) -> &[u8] {
    let off = info.OffsetToFileName as usize;
    if off >= info.FullPathName.len() {
        if let Some(pos) = info.FullPathName.iter().position(|&b| b == 0) {
            &info.FullPathName[..pos]
        } else {
            &info.FullPathName[..]
        }
    } else {
        let slice = &info.FullPathName[off..];
        if let Some(pos) = slice.iter().position(|&b| b == 0) {
            &slice[..pos]
        } else {
            slice
        }
    }
}

pub fn module_base_and_name(info: &RTL_PROCESS_MODULE_INFORMATION) -> (PVOID, &[u8]) {
    (info.ImageBase, filename_from_info(info))
}


pub fn init_object_attributes(obj: &mut OBJECT_ATTRIBUTES, name: *mut UNICODE_STRING, attributes: u32) {
    obj.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    obj.RootDirectory = ptr::null_mut();
    obj.ObjectName = name;
    obj.Attributes = attributes;
    obj.SecurityDescriptor = ptr::null_mut();
    obj.SecurityQualityOfService = ptr::null_mut();
}