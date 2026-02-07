use core::ptr;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use crate::*;

pub struct KernelAllocator;
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let size = core::cmp::max(layout.size(), 1);
            let align = core::cmp::max(layout.align(), size_of::<usize>());
            let header = size_of::<usize>();

            let total = size.checked_add(align).and_then(|v| v.checked_add(header)).unwrap_or(0);

            if total == 0 {
                return ptr::null_mut();
            }

            let raw = ExAllocatePool(_POOL_TYPE_NonPagedPool, total as _) as *mut u8;
            if raw.is_null() {
                return ptr::null_mut();
            }

            let start = raw.add(header);
            let offset = (align - (start as usize % align)) % align;
            let aligned = start.add(offset);

            let header_ptr = aligned.sub(header) as *mut usize;
            header_ptr.write(raw as usize);

            aligned
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            if ptr.is_null() {
                return;
            }
            let header_ptr = ptr.sub(size_of::<usize>()) as *mut usize;
            let raw = header_ptr.read() as *mut c_void;
            if !raw.is_null() {
                ExFreePool(raw as PVOID);
            }
        }
    }
}


