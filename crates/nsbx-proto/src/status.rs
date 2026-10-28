//! Binary status record written by the sandbox init and checked by the warden.
//!
//! Layout, big-endian: `NSBX` | exit i32 | count u32 | records.
//! Each record is path_len u16 | path | size u64 | sha256 32 | risk u8 |
//! data_len u32 | data. A truncated buffer is an error. When `data` is present
//! its length must equal `size` and its SHA-256 must equal the recorded hash.

use sha2::{Digest, Sha256};

pub struct Item {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub risk: bool,
    pub data: Vec<u8>,
}

pub struct Decoded {
    pub exit_code: i32,
    pub items: Vec<Item>,
}

const MAGIC: &[u8; 4] = b"NSBX";
const MAX_ITEMS: usize = 32;
const MAX_PATH: usize = 255;
const MAX_DATA: usize = 65_536;

pub fn digest(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

pub fn encode(exit_code: i32, items: &[Item]) -> Result<Vec<u8>, String> {
    if items.len() > MAX_ITEMS {
        return Err("too many artefacts".into());
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&exit_code.to_be_bytes());
    let count = u32::try_from(items.len()).map_err(|_| "artefact count".to_string())?;
    out.extend_from_slice(&count.to_be_bytes());
    for item in items {
        let path = item.path.as_bytes();
        if path.is_empty() || path.len() > MAX_PATH {
            return Err("artefact path length".into());
        }
        let path_len = u16::try_from(path.len()).map_err(|_| "artefact path length".to_string())?;
        out.extend_from_slice(&path_len.to_be_bytes());
        out.extend_from_slice(path);
        out.extend_from_slice(&item.size.to_be_bytes());
        out.extend_from_slice(&item.sha256);
        out.push(u8::from(item.risk));
        if item.data.len() > MAX_DATA {
            return Err("artefact is too large".into());
        }
        let data_len = u32::try_from(item.data.len()).map_err(|_| "artefact size".to_string())?;
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(&item.data);
    }
    Ok(out)
}

pub fn decode(buf: &[u8]) -> Result<Decoded, String> {
    if buf.len() < 12 {
        return Err("status record is truncated".into());
    }
    if &buf[0..4] != MAGIC {
        return Err("status record has the wrong magic".into());
    }
    let exit_code = i32::from_be_bytes(take(buf, 4)?);
    let count = u32::from_be_bytes(take(buf, 8)?);
    if count as usize > MAX_ITEMS {
        return Err("status record has too many artefacts".into());
    }
    let mut rest = &buf[12..];
    let mut items = Vec::new();
    for _ in 0..count {
        if rest.len() < 2 {
            return Err("status record is truncated".into());
        }
        let path_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if path_len == 0 || path_len > MAX_PATH || rest.len() < path_len {
            return Err("status record is truncated".into());
        }
        let path = std::str::from_utf8(&rest[..path_len])
            .map_err(|_| "status path is not utf-8".to_string())?
            .to_string();
        rest = &rest[path_len..];
        if rest.len() < 45 {
            return Err("status record is truncated".into());
        }
        let size = u64::from_be_bytes(take(rest, 0)?);
        let sha256 = take::<32>(rest, 8)?;
        let risk = rest[40] != 0;
        let data_len = u32::from_be_bytes(take(rest, 41)?) as usize;
        rest = &rest[45..];
        if data_len > MAX_DATA || rest.len() < data_len {
            return Err("status record is truncated".into());
        }
        let data = rest[..data_len].to_vec();
        rest = &rest[data_len..];
        if data_len as u64 != size {
            return Err("status size does not match the bytes".into());
        }
        if digest(&data) != sha256 {
            return Err("status hash does not match the bytes".into());
        }
        items.push(Item {
            path,
            size,
            sha256,
            risk,
            data,
        });
    }
    if !rest.is_empty() {
        return Err("status record has trailing bytes".into());
    }
    Ok(Decoded { exit_code, items })
}

pub fn json_line(exit_code: i32, items: &[Item]) -> String {
    let mut line = format!("{{\"exit\":{exit_code},\"artifacts\":[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        let hex: String = item.sha256.iter().map(|b| format!("{b:02x}")).collect();
        let risk = if item.risk { "true" } else { "false" };
        line.push_str(&format!(
            "{{\"path\":\"{}\",\"size\":{},\"sha256\":\"{hex}\",\"host_executable_risk\":{risk}}}",
            item.path, item.size
        ));
    }
    line.push_str("]}");
    line
}

fn take<const N: usize>(buf: &[u8], at: usize) -> Result<[u8; N], String> {
    let Some(bytes) = buf.get(at..at + N) else {
        return Err("status record is truncated".into());
    };
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_a_short_buffer_is_rejected() {
        let data = b"hi".to_vec();
        let item = Item {
            path: "out/note".into(),
            size: 2,
            sha256: digest(&data),
            risk: false,
            data,
        };
        let bytes = encode(0, &[item]).expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.exit_code, 0);
        assert_eq!(decoded.items[0].path, "out/note");
        assert!(!decoded.items[0].risk);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(decode(&bad).is_err());
    }
}
