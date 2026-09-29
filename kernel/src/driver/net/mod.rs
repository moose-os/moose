//! # Network driver layer
//!
//! Core types shared by the whole network stack.
//!

use alloc::{
    fmt, format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub mod nic;
pub mod proto;
pub mod rx_process_thread;

pub use nic::NetworkCard;
pub use rx_process_thread::{RxProcessThread, spawn_rx_worker};

use crate::subsystem::sync::IrqGuardedRwLock;

/// A 48-bit Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The Ethernet broadcast address, `FF:FF:FF:FF:FF:FF`.
    pub fn broadcast() -> Self {
        Self([0xFF; 6])
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

/// An IPv4 address: four octets in network order.
#[repr(C, packed)]
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout, Ord, PartialOrd,
)]
pub struct Ipv4Addr {
    octets: [u8; 4],
}

impl From<[u8; 4]> for Ipv4Addr {
    #[inline]
    fn from(octets: [u8; 4]) -> Self {
        Ipv4Addr::new(octets)
    }
}

impl Ipv4Addr {
    /// Create a new IPv4 address from raw bytes.
    pub const fn new(octets: [u8; 4]) -> Self {
        Self { octets }
    }

    /// Access raw octets.
    pub fn octets(&self) -> [u8; 4] {
        self.octets
    }

    /// `0.0.0.0`.
    pub const fn unspecified() -> Self {
        Self::new([0, 0, 0, 0])
    }

    /// `255.255.255.255`.
    pub const fn broadcast() -> Self {
        Self::new([255, 255, 255, 255])
    }
}

/// Address as a host-order integer, first octet in the top byte.
impl From<Ipv4Addr> for u32 {
    fn from(ip: Ipv4Addr) -> Self {
        let [a, b, c, d] = ip.octets;

        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }
}

impl From<u32> for Ipv4Addr {
    fn from(ip_u32: u32) -> Self {
        let a = (ip_u32 >> 24) as u8;
        let b = (ip_u32 >> 16) as u8;
        let c = (ip_u32 >> 8) as u8;
        let d = ip_u32 as u8;

        Self::new([a, b, c, d])
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Index of an interface in the [`NetworkInterfaceTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkInterfaceId(pub u16);

/// One network interface: its identity, its IPv4 address (once it has
/// one) and the card behind it.
#[derive(Clone)]
pub struct NetworkInterface {
    pub interface_id: NetworkInterfaceId,
    pub local_mac_address: MacAddress,
    pub local_internet_address: Option<Ipv4Addr>,
    pub nic: Option<Arc<dyn NetworkCard>>,
}

impl fmt::Debug for NetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkInterface")
            .field("interface_id", &self.interface_id)
            .field("local_mac_address", &self.local_mac_address)
            .field("local_internet_address", &self.local_internet_address)
            .field("nic", &self.nic.is_some())
            .finish()
    }
}

/// Maximum number of interfaces.
pub const MAX_NETWORK_INTERFACES: usize = 64;

const _: () = assert!(MAX_NETWORK_INTERFACES <= u64::BITS as usize);

/// Fixed-size registry of network interfaces.
pub struct NetworkInterfaceTable {
    /// Array of NICs.
    entries: IrqGuardedRwLock<[NetworkInterface; MAX_NETWORK_INTERFACES]>,

    /// Bit `i` set = slot `i` holds a real interface.
    occupied: AtomicU64,
}

impl NetworkInterfaceTable {
    pub fn new(default: NetworkInterface) -> Self {
        Self {
            entries: IrqGuardedRwLock::new([(); MAX_NETWORK_INTERFACES].map(|_| default.clone())),
            occupied: AtomicU64::new(0),
        }
    }

    /// Registers an interface in the first free slot and returns its ID,
    /// or `None` if the table is full.
    pub fn insert(&self, interface: NetworkInterface) -> Option<NetworkInterfaceId> {
        let mut entries = self.entries.write();

        let free_mask = !self.occupied.load(Ordering::Acquire);
        if free_mask == 0 {
            return None;
        }

        let index = free_mask.trailing_zeros() as usize;
        let id = NetworkInterfaceId(index as u16);

        let mut interface = interface;
        interface.interface_id = id;
        entries[index] = interface;

        self.occupied.fetch_or(1u64 << index, Ordering::Release);

        Some(id)
    }

    /// Calls `f` for every registered interface.
    pub fn for_each_occupied(&self, mut f: impl FnMut(NetworkInterfaceId, &NetworkInterface)) {
        let occupied = self.occupied.load(Ordering::Acquire);
        if occupied == 0 {
            return;
        }

        let snapshot: Vec<(NetworkInterfaceId, NetworkInterface)> = {
            let entries = self.entries.read();
            (0..MAX_NETWORK_INTERFACES)
                .filter(|index| (occupied & (1u64 << index)) != 0)
                .map(|index| (NetworkInterfaceId(index as u16), entries[index].clone()))
                .collect()
        };

        for (id, interface) in &snapshot {
            f(*id, interface);
        }
    }

    /// Calls `f` for every attached card.
    pub fn for_each_nic(&self, mut f: impl FnMut(&dyn NetworkCard)) {
        let occupied = self.occupied.load(Ordering::Acquire);
        let nics: Vec<Arc<dyn NetworkCard>> = {
            let entries = self.entries.read();
            let mut nics = Vec::new();

            for index in 0..MAX_NETWORK_INTERFACES {
                if (occupied & (1u64 << index)) == 0 {
                    continue;
                }
                if let Some(nic) = entries[index].nic.as_ref() {
                    nics.push(Arc::clone(nic));
                }
            }

            nics
        };

        for nic in nics {
            f(nic.as_ref());
        }
    }

    /// Returns a copy of the interface.
    pub fn get(&self, id: NetworkInterfaceId) -> Option<NetworkInterface> {
        let index = id.0 as usize;
        if index >= MAX_NETWORK_INTERFACES {
            return None;
        }

        let mask = 1u64 << index;

        if (self.occupied.load(Ordering::Acquire) & mask) == 0 {
            return None;
        }

        Some(self.entries.read()[index].clone())
    }

    /// Modifies an interface in place.
    pub fn update(&self, id: NetworkInterfaceId, f: impl FnOnce(&mut NetworkInterface)) -> bool {
        let index = id.0 as usize;
        if index >= MAX_NETWORK_INTERFACES {
            return false;
        }

        let mask = 1u64 << index;

        if (self.occupied.load(Ordering::Acquire) & mask) == 0 {
            return false;
        }

        let mut entries = self.entries.write();

        f(&mut entries[index]);

        true
    }
}

use crate::subsystem::clock::time::{Duration, Instant};

/// One slot of a [`TtlCache`].
#[derive(Debug, Clone, Copy)]
struct CacheEntry<K: Copy, V: Copy> {
    is_occupied: bool,
    key: K,
    value: V,
    expires_at: Option<Instant>,
    last_access_at: Option<Instant>,
}

impl<K: Copy, V: Copy> CacheEntry<K, V> {
    pub const fn empty(key: K, value: V) -> Self {
        Self {
            is_occupied: false,
            key,
            value,
            expires_at: None,
            last_access_at: None,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        match self.expires_at {
            Some(expires_at) => now >= expires_at,
            None => true,
        }
    }
}

/// Fixed-capacity cache with per-entry expiry and no heap allocation.
pub struct TtlCache<K: Copy + Eq, V: Copy, const N: usize> {
    entries: IrqGuardedRwLock<[CacheEntry<K, V>; N]>,
    default_time_to_live: Duration,
}

impl<K: Copy + Eq, V: Copy, const N: usize> TtlCache<K, V, N> {
    /// Creates an empty cache.
    pub const fn new(empty_key: K, empty_value: V, default_time_to_live: Duration) -> Self {
        Self {
            entries: IrqGuardedRwLock::new([CacheEntry::empty(empty_key, empty_value); N]),
            default_time_to_live,
        }
    }

    /// Looks up a key.
    pub fn lookup(&self, key: K) -> Option<V> {
        let now = Instant::now();
        let mut entries = self.entries.write();

        for entry in entries.iter_mut() {
            if !entry.is_occupied || entry.key != key {
                continue;
            }

            if entry.is_expired(now) {
                entry.is_occupied = false;
                entry.expires_at = None;
                entry.last_access_at = None;
                return None;
            }

            entry.last_access_at = Some(now);
            return Some(entry.value);
        }

        None
    }

    /// Inserts with the cache's default TTL.
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_time_to_live);
    }

    /// Inserts with a custom TTL.
    pub fn insert_with_ttl(&self, key: K, value: V, time_to_live: Duration) {
        let now = Instant::now();
        let expires_at = Some(now + time_to_live);

        let mut entries = self.entries.write();

        // 1) Update an existing entry.
        for entry in entries.iter_mut() {
            if entry.is_occupied && entry.key == key {
                entry.value = value;
                entry.expires_at = expires_at;
                entry.last_access_at = Some(now);
                return;
            }
        }

        // 2) Reuse a free or expired slot.
        for entry in entries.iter_mut() {
            if !entry.is_occupied || entry.is_expired(now) {
                *entry = CacheEntry {
                    is_occupied: true,
                    key,
                    value,
                    expires_at,
                    last_access_at: Some(now),
                };
                return;
            }
        }

        // 3) Full: evict the least recently used.
        let mut lru_index = 0usize;
        for i in 1..N {
            let a = entries[i].last_access_at;
            let b = entries[lru_index].last_access_at;

            let i_is_older = match (a, b) {
                (None, None) => false,
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (Some(ai), Some(bi)) => ai < bi,
            };

            if i_is_older {
                lru_index = i;
            }
        }

        entries[lru_index] = CacheEntry {
            is_occupied: true,
            key,
            value,
            expires_at,
            last_access_at: Some(now),
        };
    }

    /// Drops every expired entry.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write();

        for entry in entries.iter_mut() {
            if entry.is_occupied && entry.is_expired(now) {
                entry.is_occupied = false;
                entry.expires_at = None;
                entry.last_access_at = None;
            }
        }
    }

    /// Number of unexpired entries.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut count = 0usize;

        let entries = self.entries.read();
        for entry in entries.iter() {
            if entry.is_occupied && !entry.is_expired(now) {
                count += 1;
            }
        }
        count
    }
}

/// An IPv4 prefix in CIDR notation, e.g. `192.168.1.0/24`. Only the
/// first `mask_len` bits of `address` matter; the rest are ignored when
/// matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Prefix {
    pub address: Ipv4Addr,
    pub mask_len: u8,
}

impl Ipv4Prefix {
    /// Panics if `mask_len > 32`.
    pub const fn new(address: Ipv4Addr, mask_len: u8) -> Self {
        assert!(mask_len <= 32, "IPv4 prefix length must be 0..=32");

        Self { address, mask_len }
    }

    /// Whether `ip` falls inside this prefix.
    #[inline]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = self.mask_u32();

        (u32::from(self.address) & mask) == (u32::from(ip) & mask)
    }

    /// The netmask as a host-order integer.
    #[inline]
    pub fn mask_u32(&self) -> u32 {
        match self.mask_len {
            0 => 0,
            32 => u32::MAX,
            n => u32::MAX << (32 - n as u32),
        }
    }
}

/// Where a route sends traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    /// Destination is on the local link: ARP for the target itself.
    Direct,

    /// Send via a router: ARP for the gateway, not the target.
    Gateway(Ipv4Addr),
}

/// One routing table row: prefix, outgoing interface, and route data.
#[derive(Debug, Clone)]
pub struct RouteEntry<V> {
    pub prefix: Ipv4Prefix,
    pub interface_id: NetworkInterfaceId,
    pub data: V,
}

/// A simple IPv4 routing table using longest prefix match (LPM).
///
/// Entries are kept sorted by descending `mask_len`, so the first
/// match in a linear scan is the longest one.
pub struct Ipv4RoutingTable<V> {
    entries: Vec<RouteEntry<V>>,
}

impl<V> Ipv4RoutingTable<V> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a route, or replaces the existing one with the same prefix
    /// on the same interface.
    pub fn insert_for_interface(
        &mut self,
        prefix: Ipv4Prefix,
        interface_id: NetworkInterfaceId,
        data: V,
    ) {
        self.entries
            .retain(|entry| entry.prefix != prefix || entry.interface_id != interface_id);

        let entry = RouteEntry {
            prefix,
            interface_id,
            data,
        };

        let pos = self
            .entries
            .iter()
            .position(|e| e.prefix.mask_len < prefix.mask_len)
            .unwrap_or(self.entries.len());

        self.entries.insert(pos, entry);
    }

    /// The best (longest-prefix) route for `ip`.
    pub fn lookup_entry(&self, ip: Ipv4Addr) -> Option<&RouteEntry<V>> {
        self.entries.iter().find(|entry| entry.prefix.contains(ip))
    }

    /// Just the route data of the best match.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&V> {
        self.lookup_entry(ip).map(|entry| &entry.data)
    }

    /// Outgoing interface plus route data of the best match.
    pub fn lookup_with_interface(&self, ip: Ipv4Addr) -> Option<(NetworkInterfaceId, &V)> {
        self.lookup_entry(ip)
            .map(|entry| (entry.interface_id, &entry.data))
    }
}

impl Ipv4RoutingTable<NextHop> {
    /// The IP to actually ARP for: the target itself for a direct route,
    /// the gateway otherwise. `None` if there's no route at all.
    pub fn resolve_next_hop(&self, target_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        self.lookup(target_ip).map(|next_hop| match next_hop {
            NextHop::Direct => target_ip,
            NextHop::Gateway(gateway_ip) => *gateway_ip,
        })
    }

    pub fn resolve_next_hop_with_interface(
        &self,
        target_ip: Ipv4Addr,
    ) -> Option<(NetworkInterfaceId, Ipv4Addr)> {
        self.lookup_with_interface(target_ip)
            .map(|(interface_id, next_hop)| {
                let next_hop_ip = match next_hop {
                    NextHop::Direct => target_ip,
                    NextHop::Gateway(gateway_ip) => *gateway_ip,
                };

                (interface_id, next_hop_ip)
            })
    }

    pub fn print(&self) {
        const COL_DEST: &str = "Destination";
        const COL_GW: &str = "Gateway";
        const COL_FLAGS: &str = "Flags";
        const COL_IF: &str = "If";

        const DIRECT_GW: &str = "-.-.-.-";

        let rows: Vec<(String, String, String, String)> = self
            .entries
            .iter()
            .map(|entry| {
                let dest = format!("{}/{}", entry.prefix.address, entry.prefix.mask_len);
                let (gateway, flags) = match entry.data {
                    NextHop::Direct => (DIRECT_GW.to_string(), "U".to_string()),
                    NextHop::Gateway(gw) => (gw.to_string(), "UG".to_string()),
                };
                (dest, gateway, flags, entry.interface_id.0.to_string())
            })
            .collect();

        let w_dest = rows
            .iter()
            .map(|r| r.0.len())
            .chain([COL_DEST.len()])
            .max()
            .unwrap_or(COL_DEST.len())
            .max(11);
        let w_gw = rows
            .iter()
            .map(|r| r.1.len())
            .chain([COL_GW.len(), DIRECT_GW.len()])
            .max()
            .unwrap_or(COL_GW.len());
        let w_flags = rows
            .iter()
            .map(|r| r.2.len())
            .chain([COL_FLAGS.len()])
            .max()
            .unwrap_or(COL_FLAGS.len())
            .max(5);
        let w_if = rows
            .iter()
            .map(|r| r.3.len())
            .chain([COL_IF.len()])
            .max()
            .unwrap_or(COL_IF.len())
            .max(2);

        let widths = [w_dest, w_gw, w_flags, w_if];

        let top = routing_table_border('┌', '┬', '┐', &widths);
        let header_div = routing_table_border('├', '┼', '┤', &widths);
        let bottom = routing_table_border('└', '┴', '┘', &widths);

        log::debug!(
            "IPv4 routing table ({} route{})",
            self.entries.len(),
            if self.entries.len() == 1 { "" } else { "s" }
        );
        log::debug!("{top}");
        log::debug!(
            "│ {:<w_dest$} │ {:<w_gw$} │ {:<w_flags$} │ {:>w_if$} │",
            COL_DEST,
            COL_GW,
            COL_FLAGS,
            COL_IF,
        );

        if rows.is_empty() {
            log::debug!("{header_div}");
            log::debug!(
                "│ {:<w_dest$} │ {:<w_gw$} │ {:<w_flags$} │ {:>w_if$} │",
                "(empty)",
                "",
                "",
                "",
            );
        } else {
            log::debug!("{header_div}");
            for (dest, gateway, flags, iface) in rows {
                log::debug!(
                    "│ {:<w_dest$} │ {:<w_gw$} │ {:<w_flags$} │ {:>w_if$} │",
                    dest,
                    gateway,
                    flags,
                    iface,
                );
            }
        }

        log::debug!("{bottom}");
        log::debug!("  U  = on-link (reachable directly on interface)");
        log::debug!("  UG = via gateway (next hop is a router)");
    }
}

/// One horizontal border line of the routing table box, sized to `widths`.
fn routing_table_border(left: char, mid: char, right: char, widths: &[usize]) -> String {
    let mut out = String::new();
    out.push(left);

    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            out.push(mid);
        }
        out.push_str(&"─".repeat(width + 2));
    }

    out.push(right);
    out
}

/// A transport endpoint pair: local and remote address and port, plus
/// the interface to send on.
#[derive(Clone, Copy, Debug)]
pub struct Socket {
    remote_port: u16,
    local_port: u16,

    remote_address: Ipv4Addr,
    local_address: Ipv4Addr,

    nic: NetworkInterfaceId,
}

impl Socket {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    pub fn local_address(&self) -> Ipv4Addr {
        self.local_address
    }

    pub fn remote_address(&self) -> Ipv4Addr {
        self.remote_address
    }

    pub fn nic(&self) -> NetworkInterfaceId {
        self.nic
    }

    pub fn new(
        local_address: Ipv4Addr,
        local_port: u16,
        remote_address: Ipv4Addr,
        remote_port: u16,
        nic: NetworkInterfaceId,
    ) -> Self {
        Self {
            local_address,
            local_port,
            remote_address,
            remote_port,
            nic,
        }
    }
}
