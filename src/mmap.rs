// copyright 2017 Kaz Wesley

#[cfg(feature = "native")]
use libc::{
    self, c_void, MADV_HUGEPAGE, MAP_ANONYMOUS, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::ptr::{self, NonNull};

#[derive(Copy, Clone, Debug)]
pub enum Policy {
    AllowSlow,
    RequireFast,
}

#[cfg(feature = "native")]
enum Type {
    Mmap,
    Malloc,
}

#[cfg(feature = "wasm")]
enum Type {
    Heap,
}

pub(crate) struct Mmap<T> {
    ptr: NonNull<T>,
    typ: Type,
}

#[cfg(feature = "native")]
impl<T> Mmap<T> {
    pub fn new_huge() -> Option<Self> {
        unsafe {
            let pmap = libc::mmap(
                ptr::null_mut(),
                size_of::<T>(),
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                -1,
                0,
            ) as *mut T;
            if pmap as *mut libc::c_void == libc::MAP_FAILED {
                return None;
            }
            Some(Mmap {
                ptr: NonNull::new(pmap)?,
                typ: Type::Mmap,
            })
        }
    }

    pub fn new_slow() -> Option<Self> {
        unsafe {
            let mut p = ptr::null_mut();
            let res = libc::posix_memalign(&mut p, size_of::<T>(), size_of::<T>());
            if res != 0 {
                return None;
            }
            libc::madvise(p, size_of::<T>(), MADV_HUGEPAGE);
            Some(Mmap {
                ptr: NonNull::new(p as *mut T)?,
                typ: Type::Malloc,
            })
        }
    }

    pub fn new(policy: Policy) -> Self {
        match policy {
            Policy::RequireFast => Self::new_huge().expect("hugepage mmap"),
            Policy::AllowSlow => Self::new_huge()
                .or_else(Self::new_slow)
                .expect("allocating memory"),
        }
    }
}

#[cfg(feature = "wasm")]
impl<T> Mmap<T> {
    pub fn new_wasm() -> Option<Self> {
        let layout = std::alloc::Layout::new::<T>();
        unsafe {
            let ptr = std::alloc::alloc(layout) as *mut T;
            if ptr.is_null() {
                None
            } else {
                // Initialize memory to zero
                ptr::write_bytes(ptr, 0, 1);
                Some(Mmap {
                    ptr: NonNull::new(ptr)?,
                    typ: Type::Heap,
                })
            }
        }
    }

    pub fn new(_policy: Policy) -> Self {
        Self::new_wasm().expect("allocating memory")
    }
}

#[cfg(feature = "native")]
impl<T> Default for Mmap<T> {
    fn default() -> Self {
        Mmap::new_huge().expect("hugepage mmap")
    }
}

#[cfg(feature = "wasm")]
impl<T> Default for Mmap<T> {
    fn default() -> Self {
        Mmap::new_wasm().expect("allocating memory")
    }
}

#[cfg(feature = "native")]
impl<T> Drop for Mmap<T> {
    fn drop(&mut self) {
        unsafe {
            match self.typ {
                Type::Mmap => {
                    libc::munmap(self.ptr.as_ptr() as *mut c_void, size_of::<T>());
                }
                Type::Malloc => libc::free(self.ptr.as_ptr() as *mut c_void),
            }
        }
    }
}

#[cfg(feature = "wasm")]
impl<T> Drop for Mmap<T> {
    fn drop(&mut self) {
        unsafe {
            match self.typ {
                Type::Heap => {
                    let layout = std::alloc::Layout::new::<T>();
                    std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
                }
            }
        }
    }
}

impl<T> Deref for Mmap<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for Mmap<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}
