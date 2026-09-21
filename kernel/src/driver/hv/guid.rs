use alloc::fmt;

#[repr(C, packed)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Guid {
    pub data: [u8; 16],
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.data;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d[3],
            d[2],
            d[1],
            d[0],
            d[5],
            d[4],
            d[7],
            d[6],
            d[8],
            d[9],
            d[10],
            d[11],
            d[12],
            d[13],
            d[14],
            d[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Guid {
    pub const fn from_str(s: &str) -> Guid {
        let bytes = parse_guid(s);

        Guid { data: bytes }
    }
}

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex character"),
    }
}

const fn parse_byte(hi: u8, lo: u8) -> u8 {
    (hex_val(hi) << 4) | hex_val(lo)
}

const fn parse_guid(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    if b.len() != 36 {
        panic!("GUID must be 36 characters long");
    }

    let mut raw = [0u8; 16];

    raw[0] = parse_byte(b[0], b[1]);
    raw[1] = parse_byte(b[2], b[3]);
    raw[2] = parse_byte(b[4], b[5]);
    raw[3] = parse_byte(b[6], b[7]);

    if b[8] != b'-' {
        panic!("Expected dash at pos 8");
    }

    raw[4] = parse_byte(b[9], b[10]);
    raw[5] = parse_byte(b[11], b[12]);

    if b[13] != b'-' {
        panic!("Expected dash at pos 13");
    }

    raw[6] = parse_byte(b[14], b[15]);
    raw[7] = parse_byte(b[16], b[17]);

    if b[18] != b'-' {
        panic!("Expected dash at pos 18");
    }

    raw[8] = parse_byte(b[19], b[20]);
    raw[9] = parse_byte(b[21], b[22]);

    if b[23] != b'-' {
        panic!("Expected dash at pos 23");
    }

    raw[10] = parse_byte(b[24], b[25]);
    raw[11] = parse_byte(b[26], b[27]);
    raw[12] = parse_byte(b[28], b[29]);
    raw[13] = parse_byte(b[30], b[31]);
    raw[14] = parse_byte(b[32], b[33]);
    raw[15] = parse_byte(b[34], b[35]);

    [
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ]
}
