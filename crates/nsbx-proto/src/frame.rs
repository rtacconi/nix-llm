//! Length-prefixed framing: `len: u32 BE | type: u8 | payload`.
//!
//! `len` counts the type byte plus the payload, so a valid frame has
//! `1 <= len <= MAX_FRAME_LEN`. The decoder is a pure function over a byte
//! slice so it can be fuzzed and model-checked without I/O.

use thiserror::Error;

/// Upper bound on `len` for every frame type.
pub const MAX_FRAME_LEN: u32 = 65_536;
/// Bytes in the length prefix.
pub const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    HelloAck = 0x02,
    Submit = 0x10,
    Accepted = 0x11,
    Rejected = 0x12,
    Started = 0x13,
    Output = 0x20,
    Credit = 0x21,
    Cancel = 0x30,
    Exited = 0x31,
    Artifact = 0x32,
    PolicyEvent = 0x33,
    Ping = 0x40,
    Pong = 0x41,
    Error = 0x7F,
}

impl FrameType {
    pub const ALL: [FrameType; 15] = [
        Self::Hello,
        Self::HelloAck,
        Self::Submit,
        Self::Accepted,
        Self::Rejected,
        Self::Started,
        Self::Output,
        Self::Credit,
        Self::Cancel,
        Self::Exited,
        Self::Artifact,
        Self::PolicyEvent,
        Self::Ping,
        Self::Pong,
        Self::Error,
    ];

    pub fn from_u8(b: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| *t as u8 == b)
    }

    /// Frames carrying a JSON object payload; all others are binary.
    pub fn is_json(self) -> bool {
        !matches!(
            self,
            Self::Output | Self::Credit | Self::Artifact | Self::Ping | Self::Pong
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub ty: FrameType,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame length {0} is zero or exceeds {MAX_FRAME_LEN}")]
    BadLength(u32),
    #[error("unknown frame type 0x{0:02x}")]
    UnknownType(u8),
    #[error("payload of {0} bytes does not fit in a frame")]
    PayloadTooLarge(usize),
}

/// Try to decode one frame from the front of `buf`.
///
/// Returns `Ok(None)` when more bytes are needed, or the frame and the number
/// of bytes it consumed. Never reads past `HEADER_LEN + len`, and rejects a bad
/// header before the body has arrived, so a peer cannot make us buffer an
/// oversized frame.
pub fn decode(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>, FrameError> {
    let Some(header) = buf.get(..HEADER_LEN) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(FrameError::BadLength(len));
    }
    let total = HEADER_LEN + len as usize;
    let Some(body) = buf.get(HEADER_LEN..total) else {
        return Ok(None);
    };
    let ty = FrameType::from_u8(body[0]).ok_or(FrameError::UnknownType(body[0]))?;
    Ok(Some((
        Frame {
            ty,
            payload: &body[1..],
        },
        total,
    )))
}

/// Append one encoded frame to `out`.
pub fn encode(ty: FrameType, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len() + 1)
        .ok()
        .filter(|l| *l <= MAX_FRAME_LEN)
        .ok_or(FrameError::PayloadTooLarge(payload.len()))?;
    out.reserve(HEADER_LEN + len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(ty as u8);
    out.extend_from_slice(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trip_each_type() {
        for ty in FrameType::ALL {
            let mut buf = Vec::new();
            encode(ty, b"abc", &mut buf).unwrap();
            let (f, n) = decode(&buf).unwrap().unwrap();
            assert_eq!((f.ty, f.payload, n), (ty, &b"abc"[..], buf.len()));
        }
    }

    #[test]
    fn partial_input_needs_more() {
        let mut buf = Vec::new();
        encode(FrameType::Ping, &[0; 8], &mut buf).unwrap();
        for cut in 0..buf.len() {
            assert_eq!(decode(&buf[..cut]), Ok(None));
        }
    }

    #[test]
    fn rejects_bad_headers_before_body() {
        assert_eq!(decode(&[0, 0, 0, 0]), Err(FrameError::BadLength(0)));
        let big = (MAX_FRAME_LEN + 1).to_be_bytes();
        assert_eq!(decode(&big), Err(FrameError::BadLength(MAX_FRAME_LEN + 1)));
        assert_eq!(
            decode(&[0, 0, 0, 1, 0x99]),
            Err(FrameError::UnknownType(0x99))
        );
    }

    #[test]
    fn rejects_oversized_payload() {
        let payload = vec![0; MAX_FRAME_LEN as usize];
        assert!(encode(FrameType::Output, &payload, &mut Vec::new()).is_err());
        let payload = vec![0; MAX_FRAME_LEN as usize - 1];
        assert!(encode(FrameType::Output, &payload, &mut Vec::new()).is_ok());
    }

    proptest! {
        #[test]
        fn decode_never_panics_and_stays_in_bounds(buf in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(Some((f, n))) = decode(&buf) {
                prop_assert!(n <= buf.len());
                prop_assert_eq!(f.payload.len() + 1 + HEADER_LEN, n);
            }
        }

        #[test]
        fn concatenated_frames_decode_in_order(payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 1..8)) {
            let mut buf = Vec::new();
            for p in &payloads {
                encode(FrameType::Output, p, &mut buf).unwrap();
            }
            let mut rest = &buf[..];
            for p in &payloads {
                let (f, n) = decode(rest).unwrap().unwrap();
                prop_assert_eq!(f.payload, &p[..]);
                rest = &rest[n..];
            }
            prop_assert!(rest.is_empty());
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every input up to 8 bytes, `decode` does not panic and any frame it
    /// returns lies within the input.
    #[kani::proof]
    #[kani::unwind(10)]
    fn decode_is_memory_safe() {
        let buf: [u8; 8] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= buf.len());
        if let Ok(Some((f, used))) = decode(&buf[..n]) {
            assert!(used <= n);
            assert!(f.payload.len() + 1 + HEADER_LEN == used);
        }
    }
}
