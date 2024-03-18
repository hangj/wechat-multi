#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CpuEndian {
    BigEndian,
    LittleEndian,
}

impl CpuEndian {
    pub fn native_endian() -> Self {
        if u16::from_ne_bytes([0u8, 1u8]) == 1 {
            return Self::BigEndian;
        } else {
            return Self::LittleEndian;
        }
    }

    pub fn opposite(self) -> Self {
        if self == Self::BigEndian {
            Self::LittleEndian
        } else {
            Self::BigEndian
        }
    }
}

#[test]
fn test() {
    let endian = CpuEndian::native_endian();
    println!("ne: {:?}", endian);
    println!("opposite: {:?}", endian.opposite());
    println!("opposite.opposite: {:?}", endian.opposite().opposite());
}
