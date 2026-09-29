//! # DNS Resolver Module
//!
//! Minimal DNS client (RFC 1035) for resolving domain names to IPv4 addresses.
//!
//! CNAME chains are followed by re-querying the target name, up to 8
//! hops, rather than expecting the server to resolve the chain and hand
//! back.
//!

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU16, Ordering};

use hashbrown::HashMap;
use x86_64::instructions::interrupts::without_interrupts;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::{
    driver::net::{Ipv4Addr, NetworkInterfaceId, proto::udp::UdpSocketHandle},
    kernel::kernel_ref,
    subsystem::{
        clock::time::{Duration, Instant},
        process::DEFAULT_THREAD_PRIORITY,
        scheduler::OneshotGate,
        sync::IrqGuardedMutex,
    },
};

/// Well-known DNS server port.
const DNS_SERVER_PORT: u16 = 53;

/// DNS receive buffer size.
const DNS_RECV_BUFFER_SIZE: usize = 512;

/// Total time budget for one query, across all retries.
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a single attempt waits for a response before retrying.
const DNS_QUERY_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Max query attempts for one resolution.
const DNS_QUERY_RETRIES: u32 = 3;

/// How long a CNAME hint is trusted before being treated as stale and
/// dropped.
const CNAME_HINT_TTL: Duration = Duration::from_secs(60);

/// Fixed 12-byte DNS message header (RFC 1035).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct DnsFrameHeader {
    /// Matches a response to the query that triggered it.
    pub transaction_id: U16,
    /// QR/Opcode/AA/TC/RD/RA/Z/RCODE, packed per RFC 1035 §4.1.1.
    pub flags: U16,

    /// Number of questions in this packet.
    pub number_of_questions: U16,

    /// Number of answers in this packet.
    pub number_of_answers: U16,

    /// Number of authority records in this packet.
    pub number_of_authority_records: U16,

    /// Number of additional records in this packet.
    pub number_of_additional_records: U16,
}

impl DnsFrameHeader {
    /// Transaction ID.
    pub fn transaction_id(&self) -> u16 {
        self.transaction_id.get()
    }

    /// Whether the QR bit marks this as a response.
    pub fn is_response(&self) -> bool {
        (self.flags.get() & 0x8000) != 0
    }

    /// The 4-bit RCODE - 0 means no error.
    pub fn response_code(&self) -> u8 {
        (self.flags.get() & 0x000F) as u8
    }
}

/// Supported DNS resource record types used by this resolver.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Mx = 15,
    Aaaa = 28,
}

impl TryFrom<u16> for DnsRecordType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::Ns),
            5 => Ok(Self::Cname),
            15 => Ok(Self::Mx),
            28 => Ok(Self::Aaaa),
            other => Err(other),
        }
    }
}

/// DNS class.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClassCode {
    IN = 1,
}

/// A DNS question section entry.
pub struct DnsQuestion {
    pub domain_name: String,
    pub record_type: DnsRecordType,
    pub class_code: DnsClassCode,
}

impl DnsQuestion {
    /// Serializes QNAME + QTYPE + QCLASS into wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for label in self.domain_name.split('.') {
            assert!(label.len() < 64, "DNS label too long");

            // Format: <length: u8><label: str>
            // so, google.com becomes
            // [6][g][o][o][g][l][e][3][c][o][m]
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }

        bytes.push(0);
        bytes.extend_from_slice(&(self.record_type as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.class_code as u16).to_be_bytes());

        bytes
    }
}

/// Parsed DNS resource record.
pub struct DnsResourceRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub class: DnsClassCode,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsResourceRecord {
    /// Parses one resource record starting at `start_offset` within the
    /// full message `payload` (needed because a compressed name can
    /// point anywhere earlier in the message, not just within this
    /// record). Returns the record and the offset of whatever comes
    /// next.
    pub fn parse(payload: &[u8], start_offset: usize) -> Option<(Self, usize)> {
        let (name, mut cursor) = Self::parse_name(payload, start_offset)?;

        if cursor + 10 > payload.len() {
            return None;
        }

        let record_type =
            DnsRecordType::try_from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]))
                .ok()?;

        let class = match u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) {
            1 => DnsClassCode::IN,
            _ => return None,
        };

        let ttl = u32::from_be_bytes([
            payload[cursor + 4],
            payload[cursor + 5],
            payload[cursor + 6],
            payload[cursor + 7],
        ]);

        let rd_length = u16::from_be_bytes([payload[cursor + 8], payload[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + rd_length > payload.len() {
            return None;
        }

        let data = payload[cursor..cursor + rd_length].to_vec();
        cursor += rd_length;

        Some((
            Self {
                name,
                record_type,
                class,
                ttl,
                data,
            },
            cursor,
        ))
    }

    /// Parses a (possibly compressed) DNS name starting at `offset`.
    ///
    /// RFC 1035 §4.1.4: a name is a sequence of length-prefixed labels
    /// terminated by a zero byte, except any label may instead be a
    /// 2-byte pointer (top two bits set) redirecting parsing elsewhere
    /// in the message - used so repeated domain suffixes don't have to
    /// be spelled out in every record.
    pub fn parse_name(payload: &[u8], offset: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut cursor = offset;
        let mut jumped = false;
        let mut end_cursor = None;
        let mut jumps = 0u8;

        while cursor < payload.len() {
            let byte = payload[cursor];

            if byte == 0 {
                cursor += 1;
                break;
            }

            // Pointer.
            if (byte & 0xC0) == 0xC0 {
                if cursor + 1 >= payload.len() {
                    return None;
                }

                let pointer = (((byte & 0x3F) as usize) << 8) | (payload[cursor + 1] as usize);

                if !jumped {
                    end_cursor = Some(cursor + 2);
                }

                cursor = pointer;
                jumped = true;
                jumps += 1;

                // Max 5 jumps to avoid infinite loops.
                if jumps > 5 {
                    return None;
                }
            } else {
                let label_len = byte as usize;
                cursor += 1;

                if cursor + label_len > payload.len() {
                    return None;
                }

                let label = core::str::from_utf8(&payload[cursor..cursor + label_len]).ok()?;
                labels.push(label.to_string());
                cursor += label_len;
            }
        }

        let final_cursor = end_cursor.unwrap_or(cursor);
        Some((labels.join("."), final_cursor))
    }
}

/// Resolver settings installed after DHCP.
#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    pub interface_id: NetworkInterfaceId,
    pub servers: Vec<Ipv4Addr>,
}

/// A cached answer for one `(name, record_type)`.
#[derive(Clone)]
struct CacheEntry {
    addresses: Vec<Ipv4Addr>,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// A query waiting on a response.
#[derive(Clone)]
struct PendingQuery {
    domain_name: String,
    record_type: DnsRecordType,
    gate: Arc<OneshotGate>,
}

/// A CNAME target seen for `(name, record_type)`.
struct CnameHint {
    target: String,
    expires_at: Instant,
}

impl CnameHint {
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Thin facade - mirrors `DhcpClient`.
pub struct DnsResolver;

impl DnsResolver {
    /// Resolves an A record using the driver's current resolver config.
    pub fn resolve_a(name: &str) -> Option<Vec<Ipv4Addr>> {
        kernel_ref().network_subsystem().dns().resolve_a(name)
    }

    /// Installs DNS servers for an interface.
    pub fn configure(config: DnsResolverConfig) {
        kernel_ref().network_subsystem().dns().configure(config);
    }
}

/// Owns the resolver's UDP socket, upstream server config, in-flight
/// queries, answer cache, and CNAME-chain hints.
pub struct DnsDriver {
    udp_socket: IrqGuardedMutex<Option<UdpSocketHandle>>,
    config: IrqGuardedMutex<Option<DnsResolverConfig>>,

    /// In-flight queries, keyed by transaction ID.
    pending: IrqGuardedMutex<HashMap<u16, PendingQuery>>,
    cache: IrqGuardedMutex<HashMap<(String, DnsRecordType), CacheEntry>>,

    /// Populated when a response has CNAME, but no A.
    cname_hints: IrqGuardedMutex<HashMap<(String, DnsRecordType), CnameHint>>,
    transaction_id: AtomicU16,
}

impl DnsDriver {
    pub fn new() -> Self {
        Self {
            udp_socket: IrqGuardedMutex::new(None),
            config: IrqGuardedMutex::new(None),
            pending: IrqGuardedMutex::new(HashMap::new()),
            cache: IrqGuardedMutex::new(HashMap::new()),
            cname_hints: IrqGuardedMutex::new(HashMap::new()),
            transaction_id: AtomicU16::new(0x1000),
        }
    }

    /// Binds an ephemeral UDP socket and spawns the receive worker.
    pub fn initialize(&self) {
        let udp = kernel_ref().network_subsystem().udp();
        let socket = udp.socket_create();
        udp.socket_bind(socket, 0)
            .expect("DNS: failed to bind ephemeral UDP socket");

        *self.udp_socket.lock() = Some(socket);

        kernel_ref()
            .spawn_kernel_thread(dns_worker, 0, DEFAULT_THREAD_PRIORITY)
            .unwrap();
    }

    /// Installs upstream DNS servers for a given interface.
    pub fn configure(&self, config: DnsResolverConfig) {
        if config.servers.is_empty() {
            log::warn!("DNS: configure() called with empty server list");

            return;
        }

        *self.config.lock() = Some(config);
    }

    /// Returns a cached A record or performs a blocking lookup.
    pub fn resolve_a(&self, domain_name: &str) -> Option<Vec<Ipv4Addr>> {
        self.resolve(domain_name, DnsRecordType::A)
    }

    /// Blocking lookup for a given record type. Checks the cache first,
    /// then queries.
    pub fn resolve(&self, domain_name: &str, record_type: DnsRecordType) -> Option<Vec<Ipv4Addr>> {
        let mut name = domain_name.to_string();

        for hop in 0..8 {
            let key = (name.clone(), record_type);

            // Try to look up the cache first.
            if let Some(entry) = self.cache.lock().get(&key)
                && entry.is_valid()
                && !entry.addresses.is_empty()
            {
                return Some(entry.addresses.clone());
            }

            // If the entry is not in cache, try to resolve it.
            match self.resolve_once(&name, record_type) {
                Some(addrs) if !addrs.is_empty() => return Some(addrs),
                _ => {}
            }

            // Handle CNAME record.
            let next = {
                let mut hints = self.cname_hints.lock();

                match hints.remove(&key) {
                    Some(hint) if hint.is_valid() => Some(hint.target),
                    _ => None,
                }
            };
            let next = next?;

            log::trace!("following CNAME {} -> {} (hop {})", name, next, hop + 1);
            name = next;
        }

        None
    }

    /// Sends one query for `domain_name`, retrying up to
    /// [`DNS_QUERY_RETRIES`] times.
    fn resolve_once(&self, domain_name: &str, record_type: DnsRecordType) -> Option<Vec<Ipv4Addr>> {
        let config = self.config.lock().clone()?;
        let server = *config.servers.first()?;
        drop(config);

        let transaction_id = self.transaction_id.fetch_add(1, Ordering::Relaxed);
        let gate = Arc::new(OneshotGate::new());

        without_interrupts(|| {
            self.pending.lock().insert(
                transaction_id,
                PendingQuery {
                    domain_name: domain_name.to_string(),
                    record_type,
                    gate: Arc::clone(&gate),
                },
            );
        });

        let overall_deadline = Instant::now() + DNS_RESOLVE_TIMEOUT;
        let key = (domain_name.to_string(), record_type);
        let mut result = None;

        for attempt in 0..DNS_QUERY_RETRIES {
            if attempt > 0 {
                log::trace!(
                    "retry {} for {} (xid={})",
                    attempt,
                    domain_name,
                    transaction_id
                );
            }

            if self
                .send_query(domain_name, record_type, transaction_id, server)
                .is_err()
            {
                break;
            }

            let attempt_deadline =
                (Instant::now() + DNS_QUERY_ATTEMPT_TIMEOUT).min(overall_deadline);
            result = self.wait_for_result_until(&gate, &key, attempt_deadline);

            if result.is_some() || gate.is_open() || Instant::now() >= overall_deadline {
                break;
            }
        }

        self.pending.lock().remove(&transaction_id);
        result
    }

    /// Worker entry point: blocking receive loop.
    pub fn worker_loop(&self) -> ! {
        let mut receive_buffer = [0u8; DNS_RECV_BUFFER_SIZE];

        loop {
            let _ = self.receive_and_process_one(&mut receive_buffer);
        }
    }

    fn wait_for_result_until(
        &self,
        gate: &OneshotGate,
        key: &(String, DnsRecordType),
        deadline: Instant,
    ) -> Option<Vec<Ipv4Addr>> {
        while Instant::now() < deadline {
            // Try to fetch record from the cache.
            if let Some(entry) = self.cache.lock().get(key)
                && entry.is_valid()
                && !entry.addresses.is_empty()
            {
                return Some(entry.addresses.clone());
            }

            if gate.is_open() {
                break;
            }

            gate.wait();
        }

        self.cache.lock().get(key).and_then(|entry| {
            if entry.is_valid() && !entry.addresses.is_empty() {
                Some(entry.addresses.clone())
            } else {
                None
            }
        })
    }

    /// Blocks for one incoming UDP datagram, parses it as a DNS
    /// response, matches it to a pending query by transaction ID *and*
    /// by the question it echoes back, and on success caches the
    /// A records.
    fn receive_and_process_one(&self, receive_buffer: &mut [u8]) -> Result<(), ()> {
        let socket = self.udp_socket.lock().ok_or(())?;
        let udp = kernel_ref().network_subsystem().udp();

        let (received_length, _sender_ip, _sender_port) =
            udp.socket_recv_from(socket, receive_buffer)?;

        let header_size = core::mem::size_of::<DnsFrameHeader>();
        if received_length < header_size {
            return Ok(());
        }

        let (header, payload) =
            DnsFrameHeader::read_from_prefix(&receive_buffer[..received_length]).map_err(|_| ())?;

        if !header.is_response() {
            return Ok(());
        }

        if header.response_code() != 0 {
            log::warn!(
                "DNS: server returned RCODE={} for xid={}",
                header.response_code(),
                header.transaction_id()
            );

            self.fail_pending(header.transaction_id());

            return Ok(());
        }

        let (question_name, mut cursor) = DnsResourceRecord::parse_name(payload, 0).ok_or(())?;
        cursor += 4; // QTYPE + QCLASS

        let request = {
            let mut pending = self.pending.lock();
            pending.remove(&header.transaction_id())
        };

        let Some(request) = request else {
            log::trace!("DNS: unsolicited response for {question_name}");

            return Ok(());
        };

        if request.domain_name != question_name {
            log::warn!(
                "DNS: xid={} question mismatch (expected {}, got {})",
                header.transaction_id(),
                request.domain_name,
                question_name
            );

            request.gate.open();

            return Ok(());
        }

        let mut addresses = Vec::new();
        // RFC 2181 §5.2: an RRset should share one TTL; take the
        // minimum seen so the cache doesn't outlive the shortest-lived
        // record in the set.
        let mut cache_ttl = u32::MAX;
        let mut cname_target = None;

        for _ in 0..header.number_of_answers.get() {
            let Some((record, next_offset)) = DnsResourceRecord::parse(payload, cursor) else {
                break;
            };

            match record.record_type {
                DnsRecordType::A if record.data.len() == 4 => {
                    cache_ttl = cache_ttl.min(record.ttl);
                    addresses.push(Ipv4Addr::new([
                        record.data[0],
                        record.data[1],
                        record.data[2],
                        record.data[3],
                    ]));
                }
                DnsRecordType::Cname => {
                    if let Some((target, _)) = DnsResourceRecord::parse_name(&record.data, 0) {
                        cname_target = Some(target);
                    }
                }
                _ => {}
            }

            cursor = next_offset;
        }

        if addresses.is_empty() {
            if let Some(target) = cname_target {
                log::info!(
                    "DNS: CNAME {} -> {} (no A records in this response, xid={})",
                    request.domain_name,
                    target,
                    header.transaction_id()
                );

                self.cname_hints.lock().insert(
                    (request.domain_name.clone(), request.record_type),
                    CnameHint {
                        target,
                        expires_at: Instant::now() + CNAME_HINT_TTL,
                    },
                );
            } else {
                log::warn!(
                    "DNS: no A records in response for {} (xid={})",
                    request.domain_name,
                    header.transaction_id()
                );
            }

            request.gate.open();
            return Ok(());
        }

        let ttl = Duration::from_secs(cache_ttl.max(1) as u64);

        self.cache.lock().insert(
            (request.domain_name.clone(), request.record_type),
            CacheEntry {
                addresses: addresses.clone(),
                expires_at: Instant::now() + ttl,
            },
        );

        request.gate.open();
        Ok(())
    }

    /// Wakes up  whatever's waiting on a query that just
    /// got an error response.
    fn fail_pending(&self, transaction_id: u16) {
        if let Some(request) = self.pending.lock().remove(&transaction_id) {
            request.gate.open();
        }
    }

    /// Builds and sends a single-question query (standard query,
    /// recursion desired) to `server`.
    fn send_query(
        &self,
        domain_name: &str,
        record_type: DnsRecordType,
        transaction_id: u16,
        server: Ipv4Addr,
    ) -> Result<(), ()> {
        let header = DnsFrameHeader {
            transaction_id: U16::new(transaction_id),
            flags: U16::new(0x0100), // standard query, recursion desired
            number_of_questions: U16::new(1),
            number_of_answers: U16::ZERO,
            number_of_authority_records: U16::ZERO,
            number_of_additional_records: U16::ZERO,
        };

        let question = DnsQuestion {
            domain_name: domain_name.to_string(),
            record_type,
            class_code: DnsClassCode::IN,
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(header.as_bytes());
        packet.extend_from_slice(&question.to_bytes());

        let socket = self.udp_socket.lock().ok_or(())?;
        let udp = kernel_ref().network_subsystem().udp();

        udp.socket_send_to(socket, &packet, server, DNS_SERVER_PORT)?;
        Ok(())
    }
}

#[allow(clippy::never_loop)]
/// Kernel thread entry point.
extern "C" fn dns_worker(_arg: u64) -> ! {
    loop {
        kernel_ref().network_subsystem().dns().worker_loop();
    }
}
