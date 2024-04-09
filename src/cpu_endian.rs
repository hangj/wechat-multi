#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CpuEndian {
    BigEndian,
    LittleEndian,
}

impl CpuEndian {
    pub fn native_endian() -> Self {
        if u16::from_ne_bytes([0u8, 1u8]) == 1 {
            Self::BigEndian
        } else {
            Self::LittleEndian
        }
    }
}
