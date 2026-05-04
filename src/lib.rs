#![no_std]

/*!
[XTS block mode](https://en.wikipedia.org/wiki/Disk_encryption_theory#XEX-based_tweaked-codebook_mode_with_ciphertext_stealing_(XTS)) implementation in Rust.

Currently this implementation supports only ciphers with 128-bit (16-byte) block size (distinct from key size). Note that AES-256 uses 128-bit blocks, so it works with this crate. If you require other cipher block sizes, please open an issue.

# Examples:

Encrypting and decrypting multiple sectors at a time:
```
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
```
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
```
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
```
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
# if false { // Removed from tests as we're not decrypting an actual NCA
assert_eq!(magic, b"NCA3"); // In older NCA versions the section index used in header encryption was different
# }

// Decrypt the rest of the header
xts.decrypt_area(&mut buffer[0x400..0xC00], 0x200, 2, get_nintendo_tweak);
```
*/

use core::convert::TryFrom;

pub use cipher::array::{self, Array};
use cipher::consts::U16;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser};

/// Xts128 block cipher. Does not implement implement BlockMode due to XTS differences detailed
/// [here](https://github.com/RustCrypto/block-ciphers/issues/48#issuecomment-574440662).
pub struct Xts128<C> {
    /// This cipher is actually used to encrypt the blocks.
    cipher_1: C,
    /// This cipher is used only to compute the tweak at each sector start.
    cipher_2: C,
}

impl<C> Xts128<C>
where
    C: BlockSizeUser<BlockSize = U16>,
{
    /// Creates a new Xts128 using two cipher instances: the first one's used to encrypt the blocks
    /// and the second one to compute the tweak at the start of each sector.
    ///
    /// Usually both ciphers are the same algorithm, the key is stored as double sized (256 bits for Aes128).
    /// When using, the key is split in half, the first half used for cipher_1 and the other for cipher_2.
    ///
    /// If you require support for different cipher types, or block sizes different than 16 bytes,
    /// open an issue.
    pub fn new(cipher_1: C, cipher_2: C) -> Xts128<C> {
        Xts128 { cipher_1, cipher_2 }
    }
}

impl<C> Xts128<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
{
    /// Encrypts a single sector in place using the given tweak.
    ///
    /// # Panics
    /// - If there's less than a single block in the sector.
    pub fn encrypt_sector(&self, sector: &mut [u8], mut tweak: Array<u8, U16>) {
        assert!(
            sector.len() >= 16,
            "AES-XTS needs at least one complete block in each sector"
        );

        // Compute tweak
        self.cipher_2.encrypt_block(&mut tweak);

        let block_count = sector.len() / 16;

        for i in (0..sector.len()).step_by(16).take(block_count - 1) {
            let block = Array::slice_as_mut_array(&mut sector[i..i + 16]).unwrap();

            xor(block, &tweak);
            self.cipher_1.encrypt_block(block);
            xor(block, &tweak);

            tweak = galois_field_128_mul_le(tweak);
        }

        {
            let block =
                Array::slice_as_mut_array(&mut sector[16 * (block_count - 1)..16 * block_count])
                    .unwrap();

            xor(block, &tweak);
            self.cipher_1.encrypt_block(block);
            xor(block, &tweak);
        }

        let remainder = sector.len() % 16;
        if remainder != 0 {
            let last_tweak = galois_field_128_mul_le(tweak);

            let (full_block, partial_block) = sector[16 * (block_count - 1)..].split_at_mut(16);
            let (last_ciphertext, cipher_plaintext) = full_block.split_at(remainder);

            let mut last_block = Array([0u8; 16]);
            last_block[..remainder].copy_from_slice(partial_block);
            last_block[remainder..].copy_from_slice(cipher_plaintext);

            xor(&mut last_block, &last_tweak);
            self.cipher_1.encrypt_block(&mut last_block);
            xor(&mut last_block, &last_tweak);

            partial_block.copy_from_slice(last_ciphertext);
            full_block.copy_from_slice(&last_block);
        }
    }

    /// Encrypts a whole area in place, usually consisting of multiple sectors.
    ///
    /// The tweak is computed at the start of every sector using get_tweak_fn(sector_index).
    /// `get_tweak_fn` is usually `get_tweak_default`.
    ///
    /// # Panics
    /// - If there's less than a single block in the last sector.
    pub fn encrypt_area(
        &self,
        area: &mut [u8],
        sector_size: usize,
        first_sector_index: u128,
        get_tweak_fn: impl Fn(u128) -> Array<u8, U16>,
    ) {
        let area_len = area.len();
        let mut chunks = area.chunks_exact_mut(sector_size);
        for (i, chunk) in (&mut chunks).enumerate() {
            let tweak = get_tweak_fn(
                u128::try_from(i).expect("usize cannot be bigger than u128") + first_sector_index,
            );
            self.encrypt_sector(chunk, tweak);
        }
        let remainder = chunks.into_remainder();

        if !remainder.is_empty() {
            let i = area_len / sector_size;
            let tweak = get_tweak_fn(
                u128::try_from(i).expect("usize cannot be bigger than u128") + first_sector_index,
            );
            self.encrypt_sector(remainder, tweak);
        }
    }
}

impl<C> Xts128<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
{
    /// Decrypts a single sector in place using the given tweak.
    ///
    /// # Panics
    /// - If there's less than a single block in the sector.
    pub fn decrypt_sector(&self, sector: &mut [u8], mut tweak: Array<u8, U16>) {
        assert!(
            sector.len() >= 16,
            "AES-XTS needs at least one complete block in each sector"
        );

        // Compute tweak
        self.cipher_2.encrypt_block(&mut tweak);

        let block_count = sector.len() / 16;

        for i in (0..sector.len()).step_by(16).take(block_count - 1) {
            let block = Array::slice_as_mut_array(&mut sector[i..i + 16]).unwrap();

            xor(block, &tweak);
            self.cipher_1.decrypt_block(block);
            xor(block, &tweak);

            tweak = galois_field_128_mul_le(tweak);
        }

        let remainder = sector.len() % 16;
        if remainder != 0 {
            let next_to_last_tweak = tweak;
            let last_tweak = galois_field_128_mul_le(tweak);

            let (full_block, partial_block) = sector[16 * (block_count - 1)..].split_at_mut(16);
            let full_block = Array::slice_as_mut_array(full_block).unwrap();

            xor(full_block, &last_tweak);
            self.cipher_1.decrypt_block(full_block);
            xor(full_block, &last_tweak);

            let (last_plaintext, cipher_plaintext) = full_block.split_at(remainder);

            let mut last_block = Array([0u8; 16]);
            last_block[..remainder].copy_from_slice(partial_block);
            last_block[remainder..].copy_from_slice(cipher_plaintext);

            xor(&mut last_block, &next_to_last_tweak);
            self.cipher_1.decrypt_block(&mut last_block);
            xor(&mut last_block, &next_to_last_tweak);

            partial_block.copy_from_slice(last_plaintext);
            full_block.copy_from_slice(&last_block);
        } else {
            let block = Array::slice_as_mut_array(&mut sector[16 * (block_count - 1)..]).unwrap();

            xor(block, &tweak);
            self.cipher_1.decrypt_block(block);
            xor(block, &tweak);
        }
    }

    /// Decrypts a whole area in place, usually consisting of multiple sectors.
    ///
    /// The tweak is computed at the start of every sector using get_tweak_fn(sector_index).
    /// `get_tweak_fn` is usually `get_tweak_default`.
    ///
    /// # Panics
    /// - If there's less than a single block in the last sector.
    pub fn decrypt_area(
        &self,
        area: &mut [u8],
        sector_size: usize,
        first_sector_index: u128,
        get_tweak_fn: impl Fn(u128) -> Array<u8, U16>,
    ) {
        let area_len = area.len();
        let mut chunks = area.chunks_exact_mut(sector_size);
        for (i, chunk) in (&mut chunks).enumerate() {
            let tweak = get_tweak_fn(
                u128::try_from(i).expect("usize cannot be bigger than u128") + first_sector_index,
            );
            self.decrypt_sector(chunk, tweak);
        }
        let remainder = chunks.into_remainder();

        if !remainder.is_empty() {
            let i = area_len / sector_size;
            let tweak = get_tweak_fn(
                u128::try_from(i).expect("usize cannot be bigger than u128") + first_sector_index,
            );
            self.decrypt_sector(remainder, tweak);
        }
    }
}

/// This is the default way to get the tweak, which just consists of separating the sector_index
/// in an array of 16 bytes in little endian byte order. May be called to get the tweak for every
/// sector or passed directly to `(en/de)crypt_area`, which will basically do that.
pub fn get_tweak_default(sector_index: u128) -> Array<u8, U16> {
    Array(sector_index.to_le_bytes())
}

#[inline(always)]
fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

fn galois_field_128_mul_le(tweak_source: Array<u8, U16>) -> Array<u8, U16> {
    let tweak_source = u128::from_le_bytes(tweak_source.0);
    // Get the special value 0x87 if the high bit is set
    let special = ((tweak_source as i128 >> 127) & 0x87) as u128;
    let tweak = tweak_source << 1 ^ special;
    Array(tweak.to_le_bytes())
}
