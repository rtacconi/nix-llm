//! FNV-1a over bytes. Used for the BPF fingerprint and the Landlock digest.

const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x100_0000_01b3;

pub fn new() -> u64 {
    OFFSET
}

pub fn mix(state: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *state ^= u64::from(*byte);
        *state = state.wrapping_mul(PRIME);
    }
}
