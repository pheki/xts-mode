# xts-mode

[XTS block mode] implementation in Rust.

Currently this implementation supports only ciphers with 128-bit (16-byte)
block size (distinct from key size). Note that AES-256 uses 128-bit blocks,
so it is supported by this crate. If you require other block sizes, feel free
to open an issue, but notice that only XTS-AES has been standardized and the
AES standard supports only 128-bit blocks.

[XTS block mode]: https://en.wikipedia.org/wiki/Disk_encryption_theory#XEX-based_tweaked-codebook_mode_with_ciphertext_stealing_(XTS)

## Security warnings

This crate has never been independently audited, use at your own risk.

All of the usual caveats of XTS apply to this crate, and its only intended
usage is disk (sector-based storage) encryption. Some of these caveats:

- It has no authentication tags, so an adversary with write access may be able
  to randomize blocks.
- An adversary with read-write access may be able to reset blocks to a previous
  value they have seen.
- It's deterministic, so passive observers may be able to infer when each block
  has changed.

I recommend reading more about XTS weaknesses before using it.

## Examples:

Encrypting and decrypting multiple sectors at a time:
```rust
use aes::Aes128;
use aes::cipher::{Array, KeyInit, consts::{U16, U32}};
use xts_mode::{Xts128, get_tweak_default};

// Load encryption key
let key: Array<u8, U32> = Array([1; 32]);
let plaintext = [5; 0x400];

// Load data to be encrypted
let mut buffer = plaintext.to_owned();

let (key_1, key_2) = key.split::<U16>();
let cipher_1 = Aes128::new(&key_1);
let cipher_2 = Aes128::new(&key_2);

let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);

let sector_size = 0x200;
let first_sector_index = 0;

// Encrypt data in the buffer
xts.encrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

// Decrypt data in the buffer
xts.decrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

assert_eq!(&buffer[..], &plaintext[..]);
```

AES-256 works too:
```rust
use aes::Aes256;
use aes::cipher::{Array, KeyInit, consts::{U32, U64}};
use xts_mode::{Xts128, get_tweak_default};

// Load the encryption key
let key: Array<u8, U64> = Array([1; 64]);
let plaintext = [5; 0x400];

// Load the data to be encrypted
let mut buffer = plaintext.to_owned();

let (key_1, key_2) = key.split::<U32>();
let cipher_1 = Aes256::new(&key_1);
let cipher_2 = Aes256::new(&key_2);

let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

let sector_size = 0x200;
let first_sector_index = 0;

xts.encrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

xts.decrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

assert_eq!(&buffer[..], &plaintext[..]);
```

Encrypting and decrypting a single sector:
```rust
use aes::Aes128;
use aes::cipher::{Array, KeyInit, consts::{U16, U32}};
use xts_mode::{Xts128, get_tweak_default};

// Load encryption key
let key: Array<u8, U32> = Array([1; 32]);

let plaintext = [5; 0x200];

// Load data to be encrypted
let mut buffer = plaintext.to_owned();

let (key_1, key_2) = key.split::<U16>();
let cipher_1 = Aes128::new(&key_1);
let cipher_2 = Aes128::new(&key_2);

let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);

let tweak = get_tweak_default(0); // 0 is the sector index

// Encrypt data in the buffer
xts.encrypt_sector(&mut buffer, tweak);

// Decrypt data in the buffer
xts.decrypt_sector(&mut buffer, tweak);

assert_eq!(&buffer[..], &plaintext[..]);
```

Decrypting a [NCA](https://switchbrew.org/wiki/NCA_Format) (nintendo content archive) header:
```rust
use aes::Aes128;
use aes::cipher::{Array, KeyInit, consts::{U16, U32}};
use xts_mode::Xts128;

pub fn get_nintendo_tweak(sector_index: u128) -> Array<u8, U16> {
    Array(sector_index.to_be_bytes())
}

// Load header key
let header_key: Array<u8, U32> = Array([0; 0x20]);

// Read header to be decrypted into buffer
let mut buffer = vec![0; 0xC00];

let (header_key_1, header_key_2) = header_key.split::<U16>();
let cipher_1 = Aes128::new(&header_key_1);
let cipher_2 = Aes128::new(&header_key_2);

let xts = Xts128::new(cipher_1, cipher_2);

// Decrypt the first 0x400 bytes of the header in 0x200 sections
xts.decrypt_area(&mut buffer[0..0x400], 0x200, 0, get_nintendo_tweak);

let magic = &buffer[0x200..0x204];
assert_eq!(magic, b"NCA3"); // In older NCA versions the section index used in header encryption was different

// Decrypt the rest of the header
xts.decrypt_area(&mut buffer[0x400..0xC00], 0x200, 2, get_nintendo_tweak);
```
