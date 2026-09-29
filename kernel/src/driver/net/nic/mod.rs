pub mod rtl8139;

pub trait NetworkCard: Send + Sync {
    fn send_packet(&self, frame: &[u8]);

    fn has_pending_rx(&self) -> bool {
        false
    }
}
