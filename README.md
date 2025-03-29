# Yellowsun

A CryptoNight hash implementation for Monero and related cryptocurrencies, with WebAssembly support.

## Features

- CryptoNight v0 and v2 hash implementation
- Native (x86_64) optimized implementation with AES-NI and SSE4.1 support
- WebAssembly support for running in browsers and Node.js

## Usage

### Native (Rust)

```rust
use yellowsun::{Algo, hash};

// Hash data using CryptoNight v0
let result = yellowsun::hash::<yellowsun::cn_aesni::Cnv0>(data);

// Using the Hasher API
let mut hasher = yellowsun::Hasher::new(Algo::Cn0, yellowsun::AllocPolicy::AllowSlow);
let blob = data.to_vec().into_boxed_slice();
let mut hashes = hasher.hashes(blob, 0..1);
let hash = hashes.next().unwrap();
```

### WebAssembly

```javascript
// In JavaScript
import init, { hash_cn0, hash_cn2, hash_cryptonight, WasmAlgo } from './yellowsun.js';

async function run() {
  // Initialize the WASM module
  await init();
  
  // Create input data (as Uint8Array)
  const data = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  
  // Hash with CryptoNight v0
  const hash0 = hash_cn0(data);
  
  // Hash with CryptoNight v2
  const hash2 = hash_cn2(data);
  
  // Using the generic API
  const hash = hash_cryptonight(data, WasmAlgo.Cn0);
}
```

## Building

### Native

```bash
cargo build --release
```

### WebAssembly

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build for web
wasm-pack build --target web --out-dir www/pkg --features wasm --no-default-features

# Or build for Node.js
wasm-pack build --target nodejs --features wasm --no-default-features
```

## WebAssembly Demo

A simple demo is included in the `www` directory. To run it:

1. Build the WASM package as shown above
2. Serve the `www` directory with a web server, e.g.:
   ```bash
   cd www
   python -m http.server
   ```
3. Open a browser and navigate to `http://localhost:8000`

## License

MIT/Apache-2.0