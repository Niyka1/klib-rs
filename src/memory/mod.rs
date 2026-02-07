use crate::wdm::*;

pub mod module;
pub mod rw;


pub const PAGE_SIZE: usize = 0x1000;
pub const MAX_RW_SIZE: usize = 0x10000;


pub fn alloc_pool(pool_type: i32, size: usize) -> PVOID {
    unsafe {
        ExAllocatePool(pool_type, size as _)
    }
}

pub fn alloc_pool_t<T>(pool_type: i32) -> PVOID {
    alloc_pool(pool_type, size_of::<T>())
}

pub fn alloc_contiguous_memory(size: usize) -> PVOID {
    unsafe {
        let lowest = PHYSICAL_ADDRESS { QuadPart: 0 };
        let highest = PHYSICAL_ADDRESS { QuadPart: i64::MAX };
        let boundary = PHYSICAL_ADDRESS { QuadPart: 0 };
        MmAllocateContiguousMemorySpecifyCacheNode(size as _, lowest, highest, boundary, _MEMORY_CACHING_TYPE_MmNonCached, MM_ANY_NODE_OK)
    }
}


pub fn alloc_contiguous_memory_t<T>() -> PVOID {
    alloc_contiguous_memory(size_of::<T>())
}



pub fn pattern_search(base: u64, img_size: usize, pattern: &[Option<u8>]) -> Option<u64> {
    unsafe {
        let plen = pattern.len();
        if plen == 0 || img_size < plen {
            return None;
        }

        let last = img_size - plen;

        for i in 0..=last {
            let start = (base + i as u64) as *const u8;
            let mut matched = true;

            for (j, pat) in pattern.iter().enumerate() {
                let mem_byte = *start.add(j);
                match pat {
                    Some(b) => {
                        if mem_byte != *b {
                            matched = false;
                            break;
                        }
                    }
                    None => {},
                }
            }

            if matched {
                return Some(base + i as u64);
            }
        }

        None
    }
}


