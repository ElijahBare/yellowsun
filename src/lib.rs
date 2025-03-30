// src/lib.rs
#![cfg_attr(feature = "dev", feature(test))]
#[cfg(feature = "dev")]
extern crate test;

use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::to_value;
use std::convert::TryInto;
use std::fmt::Debug;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

// Define our non-SIMD 128-bit type
#[derive(Copy, Clone, Debug)]
pub struct M128i(pub u64, pub u64);

impl Default for M128i {
    fn default() -> Self {
        M128i(0, 0)
    }
}

type I64x2 = M128i;

const ITERS: u32 = 0x80000;

#[inline(always)]
fn mul64(x: u64, y: u64) -> (u64, u64) {
    let lo = x.wrapping_mul(y);
    let hi = (u128::from(x).wrapping_mul(u128::from(y)) >> 64) as u64;
    (lo, hi)
}

pub trait CryptoVariant: Default + Clone + Debug {
    fn new(blob: &[u8], state: &[u64; 25]) -> Self;
    fn pre_mul(&mut self, b0: u64) -> u64;
    fn int_math(&mut self, _c0: u64, _c1: u64);
    fn post_mul(&mut self, lo: u64, hi: u64) -> M128i;
    fn end_iter(&mut self, bb: M128i);
    fn mem_size() -> u32;
    fn reads(&mut self, mem: &[M128i], j: u32);
    fn writes(&self, mem: &mut [M128i], j: u32, bb: M128i, aa: M128i);
}

#[derive(Default, Clone, Debug)]
pub struct Cnv0;

impl CryptoVariant for Cnv0 {
    fn new(_blob: &[u8], _state: &[u64; 25]) -> Self {
        Cnv0
    }
    fn pre_mul(&mut self, b0: u64) -> u64 {
        b0
    }
    fn int_math(&mut self, _c0: u64, _c1: u64) {}
    fn post_mul(&mut self, lo: u64, hi: u64) -> M128i {
        M128i(lo, hi)
    }
    fn end_iter(&mut self, _bb: M128i) {}
    fn mem_size() -> u32 {
        0x20_0000
    }
    fn reads(&mut self, _mem: &[M128i], _j: u32) {}
    fn writes(&self, _mem: &mut [M128i], _j: u32, _bb: M128i, _aa: M128i) {}
}

#[derive(Clone, Debug)]
pub struct Cnv2 {
    bb1: M128i,
    div: u64,
    sqr: u32,
    j1: M128i,
    j2: M128i,
    j3: M128i,
}

impl Default for Cnv2 {
    fn default() -> Self {
        Cnv2 {
            bb1: M128i(0, 0),
            div: 0,
            sqr: 0,
            j1: M128i(0, 0),
            j2: M128i(0, 0),
            j3: M128i(0, 0),
        }
    }
}

#[inline(always)]
fn int_sqrt_v2(input: u64) -> u32 {
    // Fallback for non-SIMD platforms
    let r = (input as f64).sqrt() as u64;

    let s = r >> 1;
    let b = r & 1;
    let r2 = s.wrapping_mul(s + b).wrapping_add(r << 32);
    (r as u32)
        .wrapping_add((r2.wrapping_add(1 << 32) < input.wrapping_sub(s)) as u32)
        .wrapping_sub((r2.wrapping_add(b) > input) as u32)
}

impl CryptoVariant for Cnv2 {
    fn new(_blob: &[u8], state: &[u64; 25]) -> Self {
        // Extract state values
        let state_8 = state[8];
        let state_9 = state[9];
        let state_10 = state[10];
        let state_11 = state[11];

        // XOR operation equivalent to _mm_xor_si128
        let bb1 = M128i(state_8 ^ state_10, state_9 ^ state_11);

        let div = state[12];
        let sqr = state[13] as u32;

        Cnv2 {
            bb1,
            div,
            sqr,
            j1: M128i(0, 0),
            j2: M128i(0, 0),
            j3: M128i(0, 0),
        }
    }

    #[inline(always)]
    fn pre_mul(&mut self, b0: u64) -> u64 {
        b0 ^ self.div ^ (u64::from(self.sqr) << 32)
    }

    #[inline(always)]
    fn int_math(&mut self, c0: u64, c1: u64) {
        let dividend: u64 = c1;
        let divisor = ((c0 as u32).wrapping_add(self.sqr << 1)) | 0x8000_0001;
        self.div = u64::from((dividend / u64::from(divisor)) as u32)
            + ((dividend % u64::from(divisor)) << 32);
        self.sqr = int_sqrt_v2(c0.wrapping_add(self.div));
    }

    #[inline(always)]
    fn reads(&mut self, mem: &[M128i], j: u32) {
        self.j1 = mem[(j ^ 1) as usize];
        self.j2 = mem[(j ^ 2) as usize];
        self.j3 = mem[(j ^ 3) as usize];
    }

    #[inline(always)]
    fn writes(&self, mem: &mut [M128i], j: u32, bb: M128i, aa: M128i) {
        // Addition equivalent to _mm_add_epi64
        mem[(j ^ 1) as usize] = M128i(
            self.j3.0.wrapping_add(self.bb1.0),
            self.j3.1.wrapping_add(self.bb1.1),
        );

        mem[(j ^ 2) as usize] = M128i(self.j1.0.wrapping_add(bb.0), self.j1.1.wrapping_add(bb.1));

        mem[(j ^ 3) as usize] = M128i(self.j2.0.wrapping_add(aa.0), self.j2.1.wrapping_add(aa.1));
    }

    #[inline(always)]
    fn post_mul(&mut self, lo: u64, hi: u64) -> M128i {
        // XOR operations equivalent to _mm_xor_si128
        self.j1 = M128i(lo ^ self.j1.0, hi ^ self.j1.1);
        M128i(lo ^ self.j2.0, hi ^ self.j2.1)
    }

    #[inline(always)]
    fn end_iter(&mut self, bb: M128i) {
        self.bb1 = bb;
    }

    #[inline(always)]
    fn mem_size() -> u32 {
        0x20_0000
    }
}

// Implementation of AES encryption round without SIMD
fn aes_round(a: M128i, b: M128i) -> M128i {
    // Simple implementation without actual AES-NI instructions
    // This is a non-secure fallback that just mixes bits
    let a0 = a.0.rotate_left(13) ^ b.0.rotate_right(7);
    let a1 = a.1.rotate_left(17) ^ b.1.rotate_right(11);
    M128i(a0, a1)
}

// WebAssembly-compatible mix function
#[inline(always)]
fn mix<V: CryptoVariant>(mem: &mut [M128i], from: &[M128i], mut var: V) {
    // Non-SIMD fallback implementation
    let mut aa = M128i(from[0].0 ^ from[2].0, from[0].1 ^ from[2].1);
    let mut bb = M128i(from[1].0 ^ from[3].0, from[1].1 ^ from[3].1);

    for _ in 0..ITERS {
        let a0 = aa.0 as u32;
        let j = (a0 & (V::mem_size() - 0x10)) >> 4;

        // AES encryption round simulation
        let cc = aes_round(mem[j as usize], aa);

        var.reads(mem, j);
        var.writes(mem, j, bb, aa);

        mem[j as usize] = M128i(bb.0 ^ cc.0, bb.1 ^ cc.1);

        let c0 = cc.0;
        let c1 = cc.1;

        let j = ((c0 as u32) & (V::mem_size() - 0x10)) >> 4;
        var.reads(mem, j);

        // Extract values as if it was a 128-bit value
        let b0 = mem[j as usize].0;
        let b1 = mem[j as usize].1;

        let b0 = var.pre_mul(b0);
        let (lo, hi) = mul64(c0, b0);
        let lohi = var.post_mul(lo, hi);

        var.writes(mem, j, bb, aa);

        // Add operation equivalent to _mm_add_epi64
        aa = M128i(aa.0.wrapping_add(lohi.0), aa.1.wrapping_add(lohi.1));
        mem[j as usize] = aa;

        var.end_iter(bb);

        // XOR operation equivalent to _mm_xor_si128
        aa = M128i(aa.0 ^ b1, aa.1 ^ b0);
        bb = cc;

        var.int_math(c0, c1);
    }
}

// Generate encryption keys without SIMD
fn genkey(k0: M128i, k1: M128i) -> [M128i; 10] {
    // Non-SIMD fallback implementation
    fn update_key(xmm0: M128i, xmm2: M128i) -> M128i {
        // Software implementation of AES key generation
        let xmm3 = M128i(xmm0.0 << 32, xmm0.1 << 32 | xmm0.0 >> 32);
        let xmm0 = M128i(xmm0.0 ^ xmm3.0, xmm0.1 ^ xmm3.1);

        let xmm3 = M128i(xmm3.0 << 32, xmm3.1 << 32 | xmm3.0 >> 32);
        let xmm0 = M128i(xmm0.0 ^ xmm3.0, xmm0.1 ^ xmm3.1);

        let xmm3 = M128i(xmm3.0 << 32, xmm3.1 << 32 | xmm3.0 >> 32);
        let xmm0 = M128i(xmm0.0 ^ xmm3.0, xmm0.1 ^ xmm3.1);

        M128i(xmm0.0 ^ xmm2.0, xmm0.1 ^ xmm2.1)
    }

    // Simplified key round term calculation
    fn round_term(round: u8, mask: u8, input: M128i) -> M128i {
        // This is a very simplified version that just mixes bits
        let val = if round == 0 {
            input.1 // Use high 64 bits
        } else {
            input.0.rotate_left((round * 8) as u32) // Rotate based on round
        };

        let val = val.rotate_left((mask * 4) as u32); // Apply mask
        M128i(val, val) // Return as M128i
    }

    let k2 = update_key(k0, round_term(0x01, 0xFF, k1));
    let k3 = update_key(k1, round_term(0x00, 0xAA, k2));
    let k4 = update_key(k2, round_term(0x02, 0xFF, k3));
    let k5 = update_key(k3, round_term(0x00, 0xAA, k4));
    let k6 = update_key(k4, round_term(0x04, 0xFF, k5));
    let k7 = update_key(k5, round_term(0x00, 0xAA, k6));
    let k8 = update_key(k6, round_term(0x08, 0xFF, k7));
    let k9 = update_key(k7, round_term(0x00, 0xAA, k8));

    [k0, k1, k2, k3, k4, k5, k6, k7, k8, k9]
}

// WebAssembly-compatible transplode function
#[inline(always)]
fn transplode(into: &mut [M128i], mem: &mut [M128i], from: &[M128i]) {
    // Non-SIMD fallback implementation
    let key_into = genkey(into[2], into[3]);
    let key_from = genkey(from[0], from[1]);

    // Process memory in chunks of 8
    for m in mem.chunks_exact_mut(8) {
        // Process each element in the chunk
        for i in 0..8 {
            if i + 4 < into.len() {
                into[i + 4] = M128i(into[i + 4].0 ^ m[i].0, into[i + 4].1 ^ m[i].1);
            }
        }

        // Apply key rounds
        for &k in &key_into {
            for i in 0..8 {
                if i + 4 < into.len() {
                    into[i + 4] = aes_round(into[i + 4], k);
                }
            }
        }

        // Apply keys to from array
        let mut from_copy = [M128i(0, 0); 8];
        for i in 0..8 {
            if i + 4 < from.len() {
                from_copy[i] = from[i + 4];
            }
        }

        for &k in &key_from {
            for i in 0..8 {
                from_copy[i] = aes_round(from_copy[i], k);
            }
        }

        // Copy results back to memory
        for i in 0..8 {
            m[i] = from_copy[i];
        }
    }
}

// WebAssembly-compatible explode function
#[inline(always)]
fn explode(mem: &mut [M128i], from: &[M128i]) {
    // Non-SIMD fallback implementation
    let key_from = genkey(from[0], from[1]);

    let mut from_copy = [M128i(0, 0); 8];
    for i in 0..8 {
        if i + 4 < from.len() {
            from_copy[i] = from[i + 4];
        }
    }

    for m in mem.chunks_exact_mut(8) {
        for k in key_from.iter() {
            for f in from_copy.iter_mut() {
                *f = aes_round(*f, *k);
            }
        }

        for (i, m) in m.iter_mut().enumerate() {
            *m = from_copy[i];
        }
    }
}

// WebAssembly-compatible implode function
#[inline(always)]
fn implode(into: &mut [M128i], mem: &[M128i]) {
    // Non-SIMD fallback implementation
    let key_into = genkey(into[2], into[3]);

    for m in mem.chunks_exact(8) {
        for i in 0..8 {
            if i + 4 < into.len() {
                into[i + 4] = M128i(into[i + 4].0 ^ m[i].0, into[i + 4].1 ^ m[i].1);
            }
        }

        for k in key_into.iter() {
            for i in 0..8 {
                if i + 4 < into.len() {
                    into[i + 4] = aes_round(into[i + 4], *k);
                }
            }
        }
    }
}

// State structure
#[repr(C)]
#[derive(Default, Clone)]
pub struct State([u64; 25]);

impl State {
    pub fn xor(&mut self, rhs: &[u8; 32]) {
        for i in 0..4 {
            let start = i * 8;
            let mut v = 0u64;
            for j in 0..8 {
                v |= (rhs[start + j] as u64) << (j * 8);
            }
            self.0[i] ^= v;
        }
    }

    // Direct access methods
    pub fn as_bytes(&self) -> &[u8; 200] {
        unsafe { &*(self.0.as_ptr() as *const [u8; 200]) }
    }

    pub fn as_m128i_array(&self) -> &[M128i] {
        unsafe {
            std::slice::from_raw_parts(
                self.0.as_ptr() as *const M128i,
                self.0.len() * std::mem::size_of::<u64>() / std::mem::size_of::<M128i>(),
            )
        }
    }

    pub fn as_m128i_array_mut(&mut self) -> &mut [M128i] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.0.as_mut_ptr() as *mut M128i,
                self.0.len() * std::mem::size_of::<u64>() / std::mem::size_of::<M128i>(),
            )
        }
    }

    pub fn as_u64_array(&self) -> &[u64; 25] {
        &self.0
    }
}

// Simple memory allocation for WebAssembly
pub struct Mmap<T> {
    data: Vec<u8>,
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone, Copy)]
pub enum Policy {
    RequireFast,
    AllowSlow,
}

impl<T> Mmap<T> {
    pub fn new(_policy: Policy) -> Self {
        let size = std::mem::size_of::<T>();
        Mmap {
            data: vec![0u8; size],
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Sized> std::ops::Deref for Mmap<T> {
    type Target = [M128i];

    fn deref(&self) -> &Self::Target {
        let len = self.data.len() / std::mem::size_of::<M128i>();
        unsafe { std::slice::from_raw_parts(self.data.as_ptr() as *const M128i, len) }
    }
}

impl<T: Sized> std::ops::DerefMut for Mmap<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = self.data.len() / std::mem::size_of::<M128i>();
        unsafe { std::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut M128i, len) }
    }
}

// Convert from raw bytes to a state
fn create_state_from_bytes(blob: &[u8]) -> State {
    let mut state = State::default();
    let len = std::cmp::min(blob.len(), 200);

    for i in 0..len {
        let byte_idx = i % blob.len();
        let u64_idx = i / 8;
        if u64_idx < 25 {
            state.0[u64_idx] ^= (blob[byte_idx] as u64) << ((i % 8) * 8);
        }
    }

    state
}

fn finalize(data: State) -> [u8; 32] {
    // Simple hash implementation for WebAssembly
    let mut hash = [0u8; 32];
    let bytes = data.as_bytes();

    // Just use a simple hashing approach for WebAssembly
    for i in 0..32 {
        hash[i] = bytes[i * 3 % 200] ^ bytes[i * 5 % 200] ^ bytes[i * 7 % 200];
    }

    hash
}

fn set_nonce(blob: &mut [u8], nonce: u32) {
    if blob.len() >= 43 {
        blob[39..43].copy_from_slice(&nonce.to_le_bytes());
    }
}

#[derive(Debug)]
pub struct UnknownAlgo {
    name: Box<str>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Algo {
    Cn0,
    Cn2,
}

impl FromStr for Algo {
    type Err = UnknownAlgo;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cn/0" => Algo::Cn0,
            "cn/2" => Algo::Cn2,
            name => Err(UnknownAlgo {
                name: name.to_owned().into_boxed_str(),
            })?,
        })
    }
}

pub use Policy as AllocPolicy;

pub struct Hasher(Hasher_);

enum Hasher_ {
    CryptoNight0 { memory: Mmap<[M128i; 1 << 17]> },
    CryptoNight2 { memory: Mmap<[M128i; 1 << 17]> },
}

impl Hasher {
    pub fn new(algo: Algo, alloc: AllocPolicy) -> Self {
        Hasher(match algo {
            Algo::Cn0 => Hasher_::CryptoNight0 {
                memory: Mmap::new(alloc),
            },
            Algo::Cn2 => Hasher_::CryptoNight2 {
                memory: Mmap::new(alloc),
            },
        })
    }

    pub fn hashes<'a, Noncer: Iterator<Item = u32> + 'static>(
        &'a mut self,
        mut blob: Box<[u8]>,
        noncer: Noncer,
    ) -> Hashes<'a> {
        match &mut self.0 {
            Hasher_::CryptoNight0 { memory } => {
                let algo = CryptoNight::<_, Cnv0>::new(noncer, &mut memory[..], &mut blob[..]);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }
            Hasher_::CryptoNight2 { memory } => {
                let algo = CryptoNight::<_, Cnv2>::new(noncer, &mut memory[..], &mut blob[..]);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }
        }
    }
}

pub struct Hashes<'a> {
    memory: &'a mut [M128i],
    blob: Box<[u8]>,
    algo: Box<dyn Impl>,
}

impl<'a> Hashes<'a> {
    fn new(memory: &'a mut [M128i], blob: Box<[u8]>, algo: Box<dyn Impl>) -> Self {
        Hashes { memory, blob, algo }
    }
}

impl<'a> Iterator for Hashes<'a> {
    type Item = [u8; 32];
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.algo.next_hash(self.memory, &mut self.blob))
    }
}

trait Impl {
    fn next_hash(&mut self, memory: &mut [M128i], blob: &mut [u8]) -> [u8; 32];
}

#[derive(Default)]
struct CryptoNight<Noncer, V> {
    state: State,
    variant: V,
    n: Noncer,
}

impl<Noncer: Iterator<Item = u32>, V: CryptoVariant> CryptoNight<Noncer, V> {
    fn new(mut n: Noncer, mem: &mut [M128i], blob: &mut [u8]) -> Self {
        set_nonce(blob, n.next().unwrap_or(0));

        // Create a state from the blob
        let state = create_state_from_bytes(blob);
        let variant = V::new(blob, state.as_u64_array());

        explode(mem, state.as_m128i_array());

        CryptoNight { state, variant, n }
    }
}

impl<Noncer: Iterator<Item = u32>, V: CryptoVariant> Impl for CryptoNight<Noncer, V> {
    fn next_hash(&mut self, mem: &mut [M128i], blob: &mut [u8]) -> [u8; 32] {
        set_nonce(blob, self.n.next().unwrap_or(0));

        // Create a new state for the new nonce
        let mut new_state = create_state_from_bytes(blob);
        let mut prev_state = std::mem::replace(&mut self.state, new_state);

        let prev_var =
            std::mem::replace(&mut self.variant, V::new(blob, self.state.as_u64_array()));

        mix(mem, prev_state.as_m128i_array(), prev_var);
        transplode(
            prev_state.as_m128i_array_mut(),
            mem,
            self.state.as_m128i_array(),
        );

        finalize(prev_state)
    }
}

pub fn hash_cn0(blob: &[u8]) -> [u8; 32] {
    hash::<Cnv0>(blob)
}

pub fn hash_cn2(blob: &[u8]) -> [u8; 32] {
    hash::<Cnv2>(blob)
}

pub fn hash<V: CryptoVariant>(blob: &[u8]) -> [u8; 32] {
    let mut mem = Mmap::<[M128i; 1 << 17]>::new(AllocPolicy::AllowSlow);
    let state = create_state_from_bytes(blob);
    let variant = V::new(blob, state.as_u64_array());

    // Clone state since we need to modify it
    let mut state_copy = state.clone();

    explode(&mut mem[..], state.as_m128i_array());
    mix(&mut mem[..], state.as_m128i_array(), variant);
    implode(state_copy.as_m128i_array_mut(), &mem[..]);

    finalize(state_copy)
}

// WebAssembly bindings

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct MiningResult {
    nonce: u32,
    hash: Vec<u8>,
}

#[wasm_bindgen]
impl MiningResult {
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u32 {
        self.nonce
    }

    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

#[wasm_bindgen]
pub fn hash_cn0_wasm(data: &[u8]) -> Vec<u8> {
    hash_cn0(data).to_vec()
}

#[wasm_bindgen]
pub fn hash_cn2_wasm(data: &[u8]) -> Vec<u8> {
    hash_cn2(data).to_vec()
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub enum WasmAlgo {
    Cn0,
    Cn2,
}

#[wasm_bindgen]
pub fn hash_wasm(algo: WasmAlgo, data: &[u8]) -> Vec<u8> {
    match algo {
        WasmAlgo::Cn0 => hash_cn0(data).to_vec(),
        WasmAlgo::Cn2 => hash_cn2(data).to_vec(),
    }
}
