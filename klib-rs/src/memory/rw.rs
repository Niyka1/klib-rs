use core::ptr;
use crate::*;

pub fn write_to_read_only_memory(dst: PVOID, src: *const u8, size: usize) -> bool {
    unsafe {
        if dst.is_null() || src.is_null() || size == 0 {
            return false;
        }

        let mdl = IoAllocateMdl(dst, size as _, 0, 0, ptr::null_mut());
        if mdl.is_null() {
            return false;
        }

        MmProbeAndLockPages(mdl, _MODE_KernelMode as _, _LOCK_OPERATION_IoWriteAccess);

        let mapping = MmMapLockedPagesSpecifyCache(mdl, _MODE_KernelMode as _, MmNonCached, ptr::null_mut(), 0, _MM_PAGE_PRIORITY_NormalPagePriority as _);
        if mapping.is_null() {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return false;
        }

        MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        ptr::copy_nonoverlapping(src, mapping as *mut u8, size);

        MmUnmapLockedPages(mapping, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        true
    }
}

#[cfg(feature = "kernel")]
pub fn read_memory_from_pid(pid: u64, addr: u64, out: &mut [u8]) -> Result<(), wdm::NTSTATUS> {
    unsafe {
        let mut src_process: PEPROCESS = ptr::null_mut();
        let status = PsLookupProcessByProcessId(pid as PVOID, &mut src_process);
        if !NT_SUCCESS(status) {
            return Err(status);
        }

        let mut bytes_copied = 0;

        let status = MmCopyVirtualMemory(src_process, addr as _, PsGetCurrentProcess(), out.as_mut_ptr() as _, out.len() as _, _MODE_KernelMode as _, &mut bytes_copied);

        ObfDereferenceObject(src_process as _);

        if !NT_SUCCESS(status) {
            return Err(status);
        }

        if bytes_copied == 0 {
            return Err(STATUS_UNSUCCESSFUL);
        }

        if bytes_copied != out.len() as _ {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }

        Ok(())
    }
}

#[cfg(feature = "kernel")]
pub fn write_memory_from_pid(pid: u64, addr: u64, buffer: &[u8]) -> Result<(), wdm::NTSTATUS> {
    unsafe {
        let mut target_process: PEPROCESS = ptr::null_mut();
        let status = PsLookupProcessByProcessId(pid as PVOID, &mut target_process);
        if !NT_SUCCESS(status) {
            return Err(status);
        }

        let mut bytes_copied = 0;

        let status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer.as_ptr() as _, target_process, addr as _, buffer.len() as _, _MODE_KernelMode as _, &mut bytes_copied);

        ObfDereferenceObject(target_process as _);

        if !NT_SUCCESS(status) {
            return Err(status);
        }

        if bytes_copied == 0 {
            return Err(STATUS_UNSUCCESSFUL);
        }

        if bytes_copied != buffer.len() as _ {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        Ok(())
    }
}