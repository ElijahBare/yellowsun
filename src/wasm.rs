// WebAssembly module for yellowsun

#[cfg(feature = "wasm")]
use crate::{Algo, AllocPolicy, Hasher};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Simple WASM exports for cryptonight functions
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn hash_cn0(data: &[u8]) -> Vec<u8> {
    crate::hash_cn0_impl(data).to_vec()
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn hash_cn2(data: &[u8]) -> Vec<u8> {
    crate::hash_cn2_impl(data).to_vec()
}

// Export the Algo enum for JavaScript/TypeScript users
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub enum WasmAlgo {
    Cn0 = 0,
    Cn2 = 1,
}

// A more flexible API that allows selecting the algorithm
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn hash_cryptonight(data: &[u8], algo: WasmAlgo) -> Vec<u8> {
    match algo {
        WasmAlgo::Cn0 => crate::hash_cn0_impl(data).to_vec(),
        WasmAlgo::Cn2 => crate::hash_cn2_impl(data).to_vec(),
    }
}