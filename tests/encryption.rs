use aes::{cipher::generic_array::GenericArray, Aes128, Aes256};
use cipher::NewBlockCipher;
use rand::Rng;
use xts_mode::{get_tweak_default, Xts128};

fn make_xts_aes_128(key: &[u8]) -> Xts128<Aes128> {
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    Xts128::<Aes128>::new(cipher_1, cipher_2)
}

fn make_xts_aes_256(key: &[u8]) -> Xts128<Aes256> {
    let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
    let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));

    Xts128::<Aes256>::new(cipher_1, cipher_2)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut key = Vec::<u8>::with_capacity(len);
    key.resize(len, 0);
    rand::thread_rng().try_fill(&mut key[..]).unwrap();
    key
}

#[test]
fn recrypt_128() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_128(&random_bytes(32));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer.clone();
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn recrypt_128_no_remainder() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_128(&random_bytes(32));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer.clone();
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn recrypt_256() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_256(&random_bytes(64));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer.clone();
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn recrypt_256_no_remainder() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_256(&random_bytes(64));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer.clone();
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

// openssl does:
//
//    memcpy(tweak.c, iv, 16);
//    (*ctx->block2) (tweak.c, tweak.c, ctx->key2);
//
// emulate get_tweak_default by providing our tweak as iv

use openssl::symm::{decrypt, encrypt, Cipher};
use std::convert::TryFrom;

struct OpensslXts {
    cipher: openssl::symm::Cipher,
    key: Vec<u8>,
}

impl OpensslXts {
    fn new(cipher: openssl::symm::Cipher, key: Vec<u8>) -> Self {
        Self { cipher, key }
    }

    fn encrypt_sector(&self, sector: &mut [u8], tweak: [u8; 16]) {
        let ciphertext = encrypt(self.cipher, &self.key[..], Some(&tweak), sector).unwrap();
        for i in 0..ciphertext.len() {
            (*sector)[i] = ciphertext[i];
        }
    }

    fn decrypt_sector(&self, sector: &mut [u8], tweak: [u8; 16]) {
        let ciphertext = decrypt(self.cipher, &self.key[..], Some(&tweak), sector).unwrap();
        for i in 0..ciphertext.len() {
            (*sector)[i] = ciphertext[i];
        }
    }

    pub fn encrypt_area(
        &self,
        area: &mut [u8],
        sector_size: usize,
        first_sector_index: u128,
        get_tweak_fn: impl Fn(u128) -> [u8; 16],
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

    pub fn decrypt_area(
        &self,
        area: &mut [u8],
        sector_size: usize,
        first_sector_index: u128,
        get_tweak_fn: impl Fn(u128) -> [u8; 16],
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

// no remainder

#[test]
fn encrypt_file_128_no_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2000);
        let mut reference = buffer.clone();

        let key = random_bytes(32);

        let xts = make_xts_aes_128(&key);
        let openssl = OpensslXts::new(Cipher::aes_128_xts(), key);

        xts.encrypt_area(&mut buffer, 0x100, 0, get_tweak_default);
        openssl.encrypt_area(&mut reference, 0x100, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn encrypt_file_256_no_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2000);
        let mut reference = buffer.clone();

        let key = random_bytes(64);

        let xts = make_xts_aes_256(&key);
        let openssl = OpensslXts::new(Cipher::aes_256_xts(), key);

        xts.encrypt_area(&mut buffer, 0x100, 0, get_tweak_default);
        openssl.encrypt_area(&mut reference, 0x100, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn decrypt_file_128_no_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2000);
        let mut reference = buffer.clone();

        let key = random_bytes(32);

        let xts = make_xts_aes_128(&key);
        let openssl = OpensslXts::new(Cipher::aes_128_xts(), key);

        xts.decrypt_area(&mut buffer, 0x100, 0, get_tweak_default);
        openssl.decrypt_area(&mut reference, 0x100, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn decrypt_file_256_no_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2000);
        let mut reference = buffer.clone();

        let key = random_bytes(64);

        let xts = make_xts_aes_256(&key);
        let openssl = OpensslXts::new(Cipher::aes_256_xts(), key);

        xts.decrypt_area(&mut buffer, 0x100, 0, get_tweak_default);
        openssl.decrypt_area(&mut reference, 0x100, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

// remainder

#[test]
fn encrypt_file_128_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2156);
        let mut reference = buffer.clone();

        let key = random_bytes(32);

        let xts = make_xts_aes_128(&key);
        let openssl = OpensslXts::new(Cipher::aes_128_xts(), key);

        xts.encrypt_area(&mut buffer, 0x20, 0, get_tweak_default);
        openssl.encrypt_area(&mut reference, 0x20, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn encrypt_file_256_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2156);
        let mut reference = buffer.clone();

        let key = random_bytes(64);

        let xts = make_xts_aes_256(&key);
        let openssl = OpensslXts::new(Cipher::aes_256_xts(), key);

        xts.encrypt_area(&mut buffer, 0x20, 0, get_tweak_default);
        openssl.encrypt_area(&mut reference, 0x20, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn decrypt_file_128_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2156);
        let mut reference = buffer.clone();

        let key = random_bytes(32);

        let xts = make_xts_aes_128(&key);
        let openssl = OpensslXts::new(Cipher::aes_128_xts(), key);

        xts.decrypt_area(&mut buffer, 0x20, 0, get_tweak_default);
        openssl.decrypt_area(&mut reference, 0x20, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}

#[test]
fn decrypt_file_256_remainder_compare_to_openssl() {
    for _ in 0..1000 {
        let mut buffer = random_bytes(0x2156);
        let mut reference = buffer.clone();

        let key = random_bytes(64);

        let xts = make_xts_aes_256(&key);
        let openssl = OpensslXts::new(Cipher::aes_256_xts(), key);

        xts.decrypt_area(&mut buffer, 0x20, 0, get_tweak_default);
        openssl.decrypt_area(&mut reference, 0x20, 0, get_tweak_default);

        assert_eq!(&buffer[..], &reference[..]);
    }
}
