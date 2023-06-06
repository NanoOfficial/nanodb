// @file: faucet_key.rs
// @author: Krisna Pranav

use byteorder::{BigEndian, ReadBytesExt};
use error::{NanoError, Result};

pub fn build_faucet_key(addr: &[u8], ts: u32) -> Result<Vec<u8>> {
    if addr.len() != 20 {
        return Err(NanoError::KeyCodecError("bad address length".to_string()));
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(addr);
    buf.extend_from_slice(&ts.to_be_bytes());
    Ok(buf)
}

#[allow(dead_code)]
pub fn decode_faucet_key(data: &[u8]) -> Result<(Vec<u8>, u32)> {
    if data.len() != 24 {
        return Err(NanoError::KeyCodecError("bad data length".to_string()));
    }
    let addr = data[0..20].to_vec();
    let ts = (&data[20..])
        .read_u32::<BigEndian>()
        .map_err(|e| NanoError::KeyCodecError(format!("{e}")))?;
    Ok((addr, ts))
}
