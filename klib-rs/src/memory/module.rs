use alloc::string::ToString;
use core::ffi::CStr;
use core::ptr;
use crate::{PsGetProcessSectionBaseAddress, PsLookupProcessByProcessId, RtlFindExportedRoutineByName, SystemModuleInformation, SystemProcessInformation, ZwQuerySystemInformation, NT_SUCCESS, RTL_PROCESS_MODULES, RTL_PROCESS_MODULE_INFORMATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, SYSTEM_PROCESS_INFORMATION};
use crate::wdm::*;


pub fn get_system_module_strc(module_name: &str) -> Result<RTL_PROCESS_MODULE_INFORMATION, NTSTATUS> {
    unsafe {
        if module_name.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }

        let module_name = module_name.to_lowercase();
        let mut required: u32 = 0;
        let mut buf: PVOID = ptr::null_mut();
        let mut buf_size: usize = 0;

        loop {
            let q_len = match buf_size.try_into() {
                Ok(v) => v,
                Err(_) => return Err(STATUS_NO_MEMORY),
            };

            let status = ZwQuerySystemInformation(SystemModuleInformation, buf, q_len, &mut required);

            if buf.is_null() {
                if required == 0 {
                    return Err(status);
                }

                if (required as usize) > 0x7FFFFFFFusize {
                    return Err(STATUS_NO_MEMORY);
                }

                buf_size = required as usize;
                buf = ExAllocatePool(_POOL_TYPE_NonPagedPool, buf_size as _);
                if buf.is_null() {
                    return Err(STATUS_NO_MEMORY);
                }
                continue;
            } else {
                if status == STATUS_INFO_LENGTH_MISMATCH {
                    ExFreePool(buf);
                    buf = ptr::null_mut();
                    buf_size = 0;
                    continue;
                } else if status != STATUS_SUCCESS {
                    ExFreePool(buf);
                    return Err(status);
                } else {
                    break;
                }
            }
        }

        if buf.is_null() {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        if buf_size < size_of::<u32>() {
            ExFreePool(buf);
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        let modules_ptr = buf as *const RTL_PROCESS_MODULES;
        let num = (*modules_ptr).NumberOfModules as usize;

        let header_size = size_of::<u32>();
        let entry_size = size_of::<RTL_PROCESS_MODULE_INFORMATION>();
        let needed = header_size.saturating_add(num.saturating_mul(entry_size));
        if needed > buf_size {
            ExFreePool(buf);
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        let first_entry_ptr = (&(*modules_ptr).Modules) as *const RTL_PROCESS_MODULE_INFORMATION;
        let entries = core::slice::from_raw_parts(first_entry_ptr, num);

        let mut out = core::mem::zeroed();
        for info in entries {
            let full = &info.FullPathName;
            let path = CStr::from_ptr(info.FullPathName.as_ptr() as _).to_string_lossy().to_lowercase();
            if path == module_name {
                out = *info;
            } else {
                let off = info.OffsetToFileName as usize;
                if off < full.len() {
                    let name_slice = &full[off..];
                    let c_name = CStr::from_ptr(name_slice.as_ptr() as _).to_string_lossy().to_lowercase();
                    if c_name == module_name {
                        out = *info;
                        break;
                    }
                }
            }
        }

        ExFreePool(buf);

        if out.ImageBase.is_null() {
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        } else {
            Ok(out)
        }
    }
}


pub fn get_system_module_base(module_name: &str) -> Result<PVOID, NTSTATUS> {
    Ok(get_system_module_strc(module_name)?.ImageBase)
}


pub fn get_proc_addr(module: PVOID, proc_name: &str) -> Result<PVOID, NTSTATUS> {

    if module.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if proc_name.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let mut proc_name = proc_name.to_string();
    proc_name.push('\0');


    unsafe {
        let addr = RtlFindExportedRoutineByName(module, proc_name.as_ptr());
        if addr.is_null() {
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        } else {
            Ok(addr as PVOID)
        }
    }
}





pub fn get_process_base_address(pid: u64) -> Result<PVOID, NTSTATUS> {
    unsafe {
        let mut process: PEPROCESS = ptr::null_mut();
        let status = PsLookupProcessByProcessId(pid as PVOID, &mut process);

        if !NT_SUCCESS(status) {
            return Err(status);
        }

        let base = PsGetProcessSectionBaseAddress(process);
        ObfDereferenceObject(process as _);

        if base.is_null() {
            return Err(STATUS_UNSUCCESSFUL);
        }

        Ok(base)
    }
}


pub unsafe fn get_process_id(process_name: *const u8) -> Result<u64, NTSTATUS> {
    unsafe {
        let mut needed = 0;
        let status = ZwQuerySystemInformation(SystemProcessInformation, ptr::null_mut(), 0, &mut needed as *mut ULONG);

        if needed == 0 {
            return Err(status);
        }

        let buffer = ExAllocatePool(_POOL_TYPE_NonPagedPool, needed as _);
        if buffer.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        let mut ansi: ANSI_STRING = ANSI_STRING { Length: 0, MaximumLength: 0, Buffer: ptr::null_mut() };
        RtlInitAnsiString(&mut ansi as *mut ANSI_STRING, process_name as _);

        let mut unicode: UNICODE_STRING = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: ptr::null_mut() };
        let status_conv = RtlAnsiStringToUnicodeString(&mut unicode as *mut UNICODE_STRING, &mut ansi as *mut ANSI_STRING, TRUE as _);
        if status_conv < 0 {
            ExFreePool(buffer);
            return Err(STATUS_UNSUCCESSFUL);
        }

        let status_sys = ZwQuerySystemInformation(SystemProcessInformation, buffer, needed, ptr::null_mut());
        if status_sys < 0 {
            RtlFreeUnicodeString(&mut unicode as *mut UNICODE_STRING);
            ExFreePool(buffer);
            return Err(status_sys);
        }

        let mut cur = buffer as *mut SYSTEM_PROCESS_INFORMATION;
        loop {
            let img = &(*cur).ImageName;
            if !img.Buffer.is_null() && img.Length > 0 {
                let cmp = RtlCompareUnicodeString(&unicode as *const UNICODE_STRING, img as *const _ as _, TRUE as _);
                if cmp == 0 {
                    let pid = (*cur).UniqueProcessId;
                    RtlFreeUnicodeString(&mut unicode as *mut UNICODE_STRING);
                    ExFreePool(buffer);
                    return Ok(pid as _);
                }
            }

            if (*cur).NextEntryOffset == 0 {
                break;
            }
            cur = (cur as *mut u8).add((*cur).NextEntryOffset as usize) as *mut SYSTEM_PROCESS_INFORMATION;
        }

        RtlFreeUnicodeString(&mut unicode as *mut UNICODE_STRING);
        ExFreePool(buffer);
        Err(STATUS_UNSUCCESSFUL)
    }
}