use std::fs;

#[macro_use]
extern crate hex_literal;
use aes::{cipher::generic_array::GenericArray, Aes128, Aes256};
use cipher::KeyInit;
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
    let mut key = vec![0; len];
    rand::thread_rng().try_fill(&mut key[..]).unwrap();
    key
}

#[test]
fn recrypt_128() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    let xts = make_xts_aes_128(&hex!(
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
    ));

    let tweak = get_tweak_default(0);
    xts.encrypt_sector(&mut buffer, tweak);
    let _encrypted = buffer;
    xts.decrypt_sector(&mut buffer, tweak);

    assert_eq!(&buffer[..], &plaintext[..]);
}

#[test]
fn recrypt_no_remainder_128() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    let xts = make_xts_aes_128(&hex!(
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
    ));

    let tweak = get_tweak_default(0);
    xts.encrypt_sector(&mut buffer, tweak);
    let _encrypted = buffer;
    xts.decrypt_sector(&mut buffer, tweak);

    assert_eq!(&buffer[..], &plaintext[..]);
}

#[test]
fn recrypt_256() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    let xts = make_xts_aes_256(&hex!(
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f"
    ));

    let tweak = get_tweak_default(0);
    xts.encrypt_sector(&mut buffer, tweak);
    let _encrypted = buffer;
    xts.decrypt_sector(&mut buffer, tweak);

    assert_eq!(&buffer[..], &plaintext[..]);
}

#[test]
fn recrypt_no_remainder_256() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    let xts = make_xts_aes_256(&hex!(
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f"
    ));

    let tweak = get_tweak_default(0);
    xts.encrypt_sector(&mut buffer, tweak);
    let _encrypted = buffer;
    xts.decrypt_sector(&mut buffer, tweak);

    assert_eq!(&buffer[..], &plaintext[..]);
}

// Test deterministically with known files, encrypted with the OpenSSL command
// line tool, for example using AES-256:
// ```
// $ openssl enc -aes-256-xts -in test_files/file_name -out test_files/file_name.aes256 -K key_in_hex -iv 0
// ```

// Seems like OpenSSL resets the tweak every 0x1000 bytes
fn get_tweak_openssl(_sector_index: u128) -> [u8; 0x10] {
    [0; 0x10]
}

#[test]
fn encrypt_file_no_remainder() {
    let mut buffer = fs::read("test_files/random_no_remainder").expect("could not read input");
    assert_eq!(buffer.len(), 0x3000);

    let xts = make_xts_aes_128(&hex!(
        "f1e4acd1ca1258b2751c538f512cd8d2d26d7867a3e1245c5c4462cd398d443e"
    ));

    xts.encrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference =
        fs::read("test_files/random_no_remainder.aes128").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn decrypt_file_no_remainder() {
    let mut buffer =
        fs::read("test_files/random_no_remainder.aes128").expect("could not read input");
    assert_eq!(buffer.len(), 0x3000);

    let xts = make_xts_aes_128(&hex!(
        "f1e4acd1ca1258b2751c538f512cd8d2d26d7867a3e1245c5c4462cd398d443e"
    ));

    xts.decrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference = fs::read("test_files/random_no_remainder").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn encrypt_file_with_remainder() {
    let mut buffer = fs::read("test_files/random_with_remainder").expect("could not read input");
    assert_eq!(buffer.len(), 20001);

    let xts = make_xts_aes_128(&hex!(
        "a5f85b18e5d06f13aa3a2dca389d776ab195a6feb1827980eb00abb0f75ea609"
    ));

    xts.encrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference =
        fs::read("test_files/random_with_remainder.aes128").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn decrypt_file_with_remainder() {
    let mut buffer =
        fs::read("test_files/random_with_remainder.aes128").expect("could not read input");
    assert_eq!(buffer.len(), 20001);

    let xts = make_xts_aes_128(&hex!(
        "a5f85b18e5d06f13aa3a2dca389d776ab195a6feb1827980eb00abb0f75ea609"
    ));

    xts.decrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference = fs::read("test_files/random_with_remainder").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn encrypt_file_no_remainder_256() {
    let mut buffer = fs::read("test_files/random_no_remainder").expect("could not read input");
    assert_eq!(buffer.len(), 0x3000);

    let xts = make_xts_aes_256(&hex!(
        "7abc23ab77076d474a7adb32126755012da76589c21da20fb67fa762b7102d7445f250417b3b86bdf6f1d33a8f5a8e04c1ba440f30b59d6828478ec232253750"
    ));

    xts.encrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference =
        fs::read("test_files/random_no_remainder.aes256").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn decrypt_file_no_remainder_256() {
    let mut buffer =
        fs::read("test_files/random_no_remainder.aes256").expect("could not read input");
    assert_eq!(buffer.len(), 0x3000);

    let xts = make_xts_aes_256(&hex!(
        "7abc23ab77076d474a7adb32126755012da76589c21da20fb67fa762b7102d7445f250417b3b86bdf6f1d33a8f5a8e04c1ba440f30b59d6828478ec232253750"
    ));

    xts.decrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference = fs::read("test_files/random_no_remainder").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn encrypt_file_with_remainder_256() {
    let mut buffer = fs::read("test_files/random_with_remainder").expect("could not read input");
    assert_eq!(buffer.len(), 20001);

    let xts = make_xts_aes_256(&hex!(
        "8e941b9fc427ca7e4b27dd8038d3d883ec6df6dd7ef6b3c38239acf2d68d9c308e8ec6027cc425a3c71b082fe1a857e3c0c39352979f9c48329a03ac0d95cdcc"
    ));

    xts.encrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference =
        fs::read("test_files/random_with_remainder.aes256").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

#[test]
fn decrypt_file_with_remainder_256() {
    let mut buffer =
        fs::read("test_files/random_with_remainder.aes256").expect("could not read input");
    assert_eq!(buffer.len(), 20001);

    let xts = make_xts_aes_256(&hex!(
        "8e941b9fc427ca7e4b27dd8038d3d883ec6df6dd7ef6b3c38239acf2d68d9c308e8ec6027cc425a3c71b082fe1a857e3c0c39352979f9c48329a03ac0d95cdcc"
    ));

    xts.decrypt_area(&mut buffer, 0x1000, 0, get_tweak_openssl);

    let reference = fs::read("test_files/random_with_remainder").expect("could not read reference");
    assert_eq!(&buffer[..], &reference[..]);
}

// Test decrypting and encrypting random keys

#[test]
fn random_key_recrypt_128() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_128(&random_bytes(32));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer;
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn random_key_recrypt_128_no_remainder() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_128(&random_bytes(32));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer;
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn random_key_recrypt_256() {
    let plaintext = b"Yu9b5QgBck wBogw5ATwAHLEV YWDPK2mS";
    assert_eq!(plaintext.len(), 34);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_256(&random_bytes(64));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer;
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[test]
fn random_key_recrypt_256_no_remainder() {
    let plaintext = b"ATwAHLEVk WDPK2m5D1ZY9QpLyW 3aK9";
    assert_eq!(plaintext.len(), 32);
    let mut buffer = plaintext.to_owned();

    for _ in 0..100 {
        let xts = make_xts_aes_256(&random_bytes(64));

        let tweak = get_tweak_default(0);
        xts.encrypt_sector(&mut buffer, tweak);
        let _encrypted = buffer;
        xts.decrypt_sector(&mut buffer, tweak);

        assert_eq!(&buffer[..], &plaintext[..]);
    }
}

#[cfg(feature = "openssl_tests")]
mod openssl_tests {
    use super::*;
    use openssl::symm::{decrypt, encrypt, Cipher};
    use std::convert::TryFrom;

    // openssl does (in crypto/modes/xts128.c):
    //
    //    memcpy(tweak.c, iv, 16);
    //    (*ctx->block2) (tweak.c, tweak.c, ctx->key2);
    //
    // emulate our code by providing our tweak as iv

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
                    u128::try_from(i).expect("usize cannot be bigger than u128")
                        + first_sector_index,
                );
                self.encrypt_sector(chunk, tweak);
            }
            let remainder = chunks.into_remainder();

            if !remainder.is_empty() {
                let i = area_len / sector_size;
                let tweak = get_tweak_fn(
                    u128::try_from(i).expect("usize cannot be bigger than u128")
                        + first_sector_index,
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
                    u128::try_from(i).expect("usize cannot be bigger than u128")
                        + first_sector_index,
                );
                self.decrypt_sector(chunk, tweak);
            }
            let remainder = chunks.into_remainder();

            if !remainder.is_empty() {
                let i = area_len / sector_size;
                let tweak = get_tweak_fn(
                    u128::try_from(i).expect("usize cannot be bigger than u128")
                        + first_sector_index,
                );
                self.decrypt_sector(remainder, tweak);
            }
        }
    }

    // Test decrypting and encrypting random bytes with random keys

    #[test]
    fn encrypt_random_bytes_128_no_remainder_compare_to_openssl() {
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
    fn encrypt_random_bytes_256_no_remainder_compare_to_openssl() {
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
    fn decrypt_random_bytes_128_no_remainder_compare_to_openssl() {
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
    fn decrypt_random_bytes_256_no_remainder_compare_to_openssl() {
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
    fn encrypt_random_bytes_128_remainder_compare_to_openssl() {
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
    fn encrypt_random_bytes_256_remainder_compare_to_openssl() {
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
    fn decrypt_random_bytes_128_remainder_compare_to_openssl() {
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
    fn decrypt_random_bytes_256_remainder_compare_to_openssl() {
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
}
