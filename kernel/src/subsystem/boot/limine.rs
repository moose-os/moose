use limine::{
    BaseRevision,
    framebuffer::Framebuffer,
    memory_map::Entry,
    paging::Mode,
    request::{
        ExecutableAddressRequest, FramebufferRequest, HhdmRequest, MemoryMapRequest,
        PagingModeRequest, RsdpRequest, StackSizeRequest,
    },
};

use crate::driver::acpi::Rsdp;

/// Sets the base revision to the latest revision supported by the crate.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
static PAGING_MODE_REQUEST: PagingModeRequest =
    PagingModeRequest::new().with_mode(Mode::FOUR_LEVEL);

#[used]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
static HIGHER_HALF_DIRECT_MAPPING_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(4 * 1024 * 1024); // 4 MiB

#[used]
static EXECUTABLE_ADDRESS_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();

pub struct LimineBootContext {
    pub memory_map_entries: &'static [&'static Entry],
    pub physical_memory_offset: u64,
    pub kernel_virtual_base_address: u64,
    pub rsdp: *const Rsdp,
    pub framebuffer: Framebuffer<'static>,
}

impl LimineBootContext {
    pub fn gather() -> Result<Self, LimineError> {
        if !BASE_REVISION.is_supported() {
            return Err(LimineError::UnsupportedRevision);
        }

        let _stack_size_response = STACK_SIZE_REQUEST
            .get_response()
            .ok_or(LimineError::StackAllocationFailed);

        let _paging_mode_response = PAGING_MODE_REQUEST
            .get_response()
            .ok_or(LimineError::UnsupportedPagingMode)?;

        let memory_map_response = MEMORY_MAP_REQUEST
            .get_response()
            .ok_or(LimineError::MemoryMapUnavailable)?;

        let higher_half_direct_mapping_response = HIGHER_HALF_DIRECT_MAPPING_REQUEST
            .get_response()
            .ok_or(LimineError::HhdmNotProvided)?;

        let kernel_virtual_base_address = EXECUTABLE_ADDRESS_REQUEST
            .get_response()
            .unwrap()
            .virtual_base();

        let rsdp_response = RSDP_REQUEST
            .get_response()
            .ok_or(LimineError::RsdpNotFound)?;

        let framebuffer_response = FRAMEBUFFER_REQUEST
            .get_response()
            .ok_or(LimineError::NoFramebufferAvailable)?;
        let framebuffer = framebuffer_response
            .framebuffers()
            .next()
            .ok_or(LimineError::NoFramebufferAvailable)?;

        Ok(Self {
            memory_map_entries: memory_map_response.entries(),
            physical_memory_offset: higher_half_direct_mapping_response.offset(),
            kernel_virtual_base_address,
            rsdp: rsdp_response.address() as *const Rsdp,
            framebuffer,
        })
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LimineError {
    #[error("unsupported revision")]
    UnsupportedRevision,
    #[error("stack allocation failed")]
    StackAllocationFailed,
    #[error("unsupported paging mode")]
    UnsupportedPagingMode,
    #[error("memory map is unavailable")]
    MemoryMapUnavailable,
    #[error("HHDM was not provided")]
    HhdmNotProvided,
    #[error("RSDP was not found")]
    RsdpNotFound,
    #[error("no framebuffer was available")]
    NoFramebufferAvailable,
}
