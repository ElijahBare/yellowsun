// copyright 2017 Kaz Wesley

//! 200-byte buffer with 1/8/16-byte views.

use skein_hash::digest::generic_array::typenum::U200;
use skein_hash::GenericArray;

#[cfg(all(feature = "native", target_arch = "x86_64"))]
use std::arch::x86_64::__m128i as i64x2;
#[cfg(not(all(feature = "native", target_arch = "x86_64")))]
type i64x2 = [u64; 2];

#[derive(Clone, Copy)]
#[repr(C, align(128))]
pub union State {
    // full-size (array interface)
    pub u8_array: [u8; 200],
    pub u64_array: [u64; 25],
    // partial!
    pub i64x2_array: [i64x2; 12],
}

impl Default for State {
    fn default() -> Self {
        State {
            u64_array: [0u64; 25],
        }
    }
}

impl From<[u64; 25]> for State {
    fn from(u64_array: [u64; 25]) -> State {
        State { u64_array }
    }
}

impl From<GenericArray<u8, U200>> for State {
    fn from(gen_array: GenericArray<u8, U200>) -> State {
        use std::mem;
        State {
            u8_array: unsafe { mem::transmute(gen_array) },
        }
    }
}

// Support for SHA3 digest from blake_hash's GenericArray
#[cfg(any(feature = "wasm", not(feature = "native")))]
impl From<sha3::digest::generic_array::GenericArray<u8, sha3::digest::generic_array::typenum::U32>> for State {
    fn from(gen_array: sha3::digest::generic_array::GenericArray<u8, sha3::digest::generic_array::typenum::U32>) -> State {
        let mut state = State::default();
        // Copy the 32 bytes from SHA3 digest into our state
        unsafe {
            state.u8_array[..32].copy_from_slice(gen_array.as_slice());
        }
        state
    }
}

// Generic function to initialize state from a hash result
pub fn init_state_from_digest(digest_bytes: &[u8]) -> State {
    let mut state = State::default();
    unsafe {
        for i in 0..digest_bytes.len() {
            if i < 200 {
                state.u8_array[i] = digest_bytes[i];
            }
        }
    }
    state
}

impl<'a> From<&'a State> for &'a [u8; 200] {
    fn from(state: &'a State) -> Self {
        unsafe { &state.u8_array }
    }
}

impl<'a> From<&'a mut State> for &'a mut [u64; 25] {
    fn from(state: &'a mut State) -> Self {
        unsafe { &mut state.u64_array }
    }
}

impl<'a> From<&'a State> for &'a [u64; 25] {
    fn from(state: &'a State) -> Self {
        unsafe { &state.u64_array }
    }
}

impl<'a> From<&'a State> for &'a [i64x2] {
    fn from(state: &'a State) -> Self {
        unsafe { &state.i64x2_array[..] }
    }
}

impl<'a> From<&'a mut State> for &'a mut [i64x2] {
    fn from(state: &'a mut State) -> Self {
        unsafe { &mut state.i64x2_array[..] }
    }
}
