//! TCP checksum.
//!
//! One's-complement checksum over a pseudo-header (parts of the IP
//! header) plus the real TCP header and payload.

/// Computes the TCP checksum (RFC 793) over `header` + `data`.
pub(super) fn calculate_tcp_checksum(
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    header: &[u8],
    data: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    let mut add_u16_be = |hi: u8, lo: u8| {
        sum = sum.wrapping_add(u16::from_be_bytes([hi, lo]) as u32);
    };

    add_u16_be(src_addr[0], src_addr[1]);
    add_u16_be(src_addr[2], src_addr[3]);
    add_u16_be(dst_addr[0], dst_addr[1]);
    add_u16_be(dst_addr[2], dst_addr[3]);
    // IPv4 pseudo-header: zero + protocol (TCP = 6)
    add_u16_be(0, 6);
    let tcp_len = (header.len() + data.len()) as u16;
    sum = sum.wrapping_add(tcp_len as u32);

    let combined = header.len() + data.len();
    let get = |i: usize| {
        if i < header.len() {
            header[i]
        } else {
            data[i - header.len()]
        }
    };

    let mut i = 0;
    while i + 1 < combined {
        sum = sum.wrapping_add(u16::from_be_bytes([get(i), get(i + 1)]) as u32);
        i += 2;
    }
    if i < combined {
        sum = sum.wrapping_add(u16::from_be_bytes([get(i), 0]) as u32);
    }

    // One's-complement addition
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
