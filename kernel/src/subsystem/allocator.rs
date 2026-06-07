use core::{
    alloc::{GlobalAlloc, Layout},
    cmp::max,
    ptr::NonNull,
};

use libm::ceilf;
use linked_list_allocator::Heap;
use spin::{Mutex, Once};

use crate::subsystem::memory::{
    CurrentAddressSpace, Exact, MemoryError, PAGE_SIZE, Page, PageFlags, VirtualAddress,
    memory_manager,
};

pub(crate) const HEAP_START: usize = 0xffffffff82220000;
const INITIAL_HEAP_SIZE: usize = 16 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: KernelHeapAllocator = KernelHeapAllocator::empty();

pub fn initialize_heap() -> Result<(), MemoryError> {
    let mut memory_manager = memory_manager().write();

    for i in 0..(INITIAL_HEAP_SIZE / PAGE_SIZE) {
        let page = Page::new(VirtualAddress::new((HEAP_START + (i * PAGE_SIZE)) as u64));
        let frame = memory_manager.allocate_frame().expect("Failed to allocate");

        unsafe {
            memory_manager.map(
                CurrentAddressSpace,
                Exact(&page, &frame),
                PageFlags::WRITABLE,
            )?
        };
    }

    unsafe {
        ALLOCATOR.initialize(HEAP_START as *mut u8, INITIAL_HEAP_SIZE);
    }

    Ok(())
}

struct KernelHeapAllocator {
    inner: Once<Mutex<KernelHeapAllocatorInner>>,
}

struct KernelHeapAllocatorInner {
    heap: Mutex<Heap>,
    currently_allocated_pages: usize,
}

impl KernelHeapAllocator {
    const fn empty() -> Self {
        Self { inner: Once::new() }
    }

    unsafe fn initialize(&self, heap_bottom: *mut u8, heap_size: usize) {
        self.inner.call_once(|| {
            let mut heap = Heap::empty();

            unsafe { heap.init(heap_bottom, heap_size) };

            Mutex::new(KernelHeapAllocatorInner {
                heap: Mutex::new(heap),
                currently_allocated_pages: heap_size / PAGE_SIZE,
            })
        });
    }
}

unsafe impl GlobalAlloc for KernelHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut inner = self.inner.get().unwrap().lock();

        let free = {
            let heap = inner.heap.lock();

            heap.free()
        };

        if layout.size() > free {
            let remaining_bytes = layout.size() - free;
            // The minimal amount of frames required to fulfill this allocation request.
            let minimal_frames = ceilf(remaining_bytes as f32 / 4096.0) as usize;
            // A little bit more than the minimal amount,
            // so that the next allocation doesn't immediately require more frame allocations (at least if it's not super large).
            let optimal_frames = max(
                round_to_next_power_of_two(minimal_frames as u64 + 1) as usize,
                16,
            );

            assert!(optimal_frames >= minimal_frames);

            let mut memory_manager = memory_manager().write();

            // Allocates the amount of frames required to fulfill this allocation request. Panics if it's not possible to do so.
            for i in 0..minimal_frames {
                let page = Page::new(VirtualAddress::new(
                    (HEAP_START + ((inner.currently_allocated_pages + i) * PAGE_SIZE)) as u64,
                ));
                let frame = memory_manager.allocate_frame().expect("Failed to allocate");

                unsafe {
                    memory_manager.map(
                        CurrentAddressSpace,
                        Exact(&page, &frame),
                        PageFlags::WRITABLE,
                    )
                }
                .unwrap();
            }

            // Tries to allocate additional frames, so there's always a bit of wiggle room. Gives up if it's not possible to do so.
            for i in minimal_frames..optimal_frames {
                let page = Page::new(VirtualAddress::new(
                    (HEAP_START + ((inner.currently_allocated_pages + i) * PAGE_SIZE)) as u64,
                ));

                if let Some(frame) = memory_manager.allocate_frame() {
                    unsafe {
                        if memory_manager
                            .map(
                                CurrentAddressSpace,
                                Exact(&page, &frame),
                                PageFlags::WRITABLE,
                            )
                            .is_err()
                        {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            inner.currently_allocated_pages += optimal_frames;

            let mut heap = inner.heap.lock();

            unsafe { heap.extend(optimal_frames * PAGE_SIZE) };
        }

        let mut heap = inner.heap.lock();

        heap.allocate_first_fit(layout)
            .ok()
            .map_or(core::ptr::null_mut(), |allocation| allocation.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = self.inner.get().unwrap().lock();

        let mut heap = inner.heap.lock();

        if let Some(ptr) = NonNull::new(ptr) {
            unsafe { heap.deallocate(ptr, layout) };
        }
    }
}

fn round_to_next_power_of_two(n: u64) -> u64 {
    // Source: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2

    if n == 0 {
        return 1;
    }

    let mut n = n;

    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n += 1;

    n
}
