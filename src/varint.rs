use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{self, Read};

/// Encodes a CompactSize (Bitcoin-style varint) into `w`.
pub fn write_compact_size(n: u64, w: &mut Vec<u8>) {
    match n {
        0..=0xfc => w.push(n as u8),
        0xfd..=0xffff => {
            w.push(0xfd);
            w.write_u16::<LittleEndian>(n as u16).unwrap();
        }
        0x1_0000..=0xffff_ffff => {
            w.push(0xfe);
            w.write_u32::<LittleEndian>(n as u32).unwrap();
        }
        _ => {
            w.push(0xff);
            w.write_u64::<LittleEndian>(n).unwrap();
        }
    }
}

/// Length (in bytes) of CompactSize encoding.
pub fn compact_size_len(n: u64) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Reads a CompactSize value from the reader.
pub fn read_compact_size(r: &mut impl Read) -> io::Result<u64> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    match tag[0] {
        n @ 0x00..=0xfc => Ok(n as u64),
        0xfd => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b)?;
            Ok(u16::from_le_bytes(b) as u64)
        }
        0xfe => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            Ok(u32::from_le_bytes(b) as u64)
        }
        0xff => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
    }
}

/// Writes CompactSize(len(data)) || data.
pub fn ser_bytes(data: &[u8], w: &mut Vec<u8>) {
    write_compact_size(data.len() as u64, w);
    w.extend_from_slice(data);
}
