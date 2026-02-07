#[cfg(feature = "kernel")]
use alloc::vec;
#[cfg(feature = "kernel")]
use core::alloc::Layout;
#[cfg(feature = "kernel")]
use iced_x86::{Decoder, DecoderOptions};
#[cfg(feature = "kernel")]
use crate::*;
#[cfg(feature = "kernel")]
use crate::memory::rw::write_to_read_only_memory;

const TRAMPOLINE_JMP_SIZE: usize = 12;
const MAX_READ_BYTES: usize = 64;
const MAX_INSN_BYTE: usize = 16;


const JMP_ABS_SIZE: usize = 12;
const MAX_DECODE: usize = 32;


fn build_abs_jump(buf: &mut [u8], target: u64) {
    buf[0] = 0x48;
    buf[1] = 0xB8;
    buf[2..10].copy_from_slice(&target.to_le_bytes());
    buf[10] = 0xFF;
    buf[11] = 0xE0;
}




#[derive(PartialOrd, PartialEq, Eq)]
pub struct Hook {
    hooked: u64,
    original_bytes: Vec<u8>,
    stub2real: *mut u8,
    unset_drop: bool,
}

impl Hook {
    pub fn get_original_function(&self) -> u64 {
        self.stub2real as u64
    }

    pub fn set_hook(addr: *mut u8, hook: u64, unset_drop: bool) -> Result<Self, NTSTATUS> {
        unsafe {
            let mut patch_len = 0usize;
            let mut stolen = Vec::new();

            while patch_len < JMP_ABS_SIZE {
                let cur_addr = addr.add(patch_len);
                let bytes = slice::from_raw_parts(cur_addr, MAX_INSN_BYTE);

                let mut decoder = Decoder::with_ip(64, bytes, cur_addr as u64, DecoderOptions::NONE);
                let insn = decoder.decode();

                let len = insn.len();
                stolen.extend_from_slice(&bytes[..len]);
                patch_len += len;
            }

            let tramp_size = stolen.len() + JMP_ABS_SIZE;
            let stub = alloc::alloc::alloc(Layout::from_size_align(tramp_size, 16).unwrap());

            if stub.is_null() {
                return Err(STATUS_NO_MEMORY);
            }

            let tramp_slice = slice::from_raw_parts_mut(stub, tramp_size);
            tramp_slice[..stolen.len()].copy_from_slice(&stolen);
            
            build_abs_jump(&mut tramp_slice[stolen.len()..], addr as u64 + patch_len as u64);
            
            let mut patch = vec![0x90u8; patch_len];
            build_abs_jump(&mut patch[..JMP_ABS_SIZE], hook);

            if !write_to_read_only_memory(addr as _, patch.as_ptr(), patch_len) {
                return Err(STATUS_NO_MEMORY);
            }

            Ok(Hook {
                hooked: addr as u64,
                original_bytes: stolen,
                stub2real: stub,
                unset_drop,
            })
        }
    }

    pub fn free_hook(&self) -> Result<(), NTSTATUS> {
        unsafe {
            if self.hooked == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }

            if !write_to_read_only_memory(self.hooked as PVOID, self.original_bytes.as_ptr(), self.original_bytes.len()) {
                return Err(STATUS_UNSUCCESSFUL);
            }

            alloc::alloc::dealloc(self.stub2real, Layout::from_size_align(self.original_bytes.len() + JMP_ABS_SIZE, 16).unwrap());
            Ok(())
        }
    }
}


impl Drop for Hook {
    fn drop(&mut self) {
        if self.unset_drop {
            let _ = self.free_hook().ok();
        }
    }
}