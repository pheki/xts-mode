#[macro_use]
extern crate criterion;

use xts_mode::{Xts128, get_tweak_default};

use aes::{Aes128, Aes256};
use cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    consts::{U16, U32, U64},
};
use criterion::{BenchmarkGroup, Criterion, measurement::Measurement};
use rand::Rng;

const BENCHED_SECTOR_SIZES: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];

fn bench_encrypt_sector<
    M: Measurement,
    R: Rng,
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
>(
    group: &mut BenchmarkGroup<M>,
    rng: &mut R,
    xts: &Xts128<C>,
) {
    let mut buffer = Vec::new();

    for size in BENCHED_SECTOR_SIZES {
        buffer.resize(size, 0);
        rng.fill_bytes(&mut buffer);
        assert_eq!(buffer.len(), size);
        group.bench_function(format!("sector size {} B", size), |benchmark| {
            let mut i = 0;
            benchmark.iter(|| {
                let tweak = get_tweak_default(i);
                xts.encrypt_sector(&mut buffer, tweak);
                i = i.wrapping_add(1);
            })
        });
    }
}

fn encryption_128(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("xts-128 aes-128 enc");

    let mut rng = rand::rng();

    let mut key: Array<u8, U32> = Array([0u8; 32]);
    rng.fill_bytes(&mut key);

    let (key_1, key_2) = key.split::<U16>();
    let cipher_1 = Aes128::new(&key_1);
    let cipher_2 = Aes128::new(&key_2);

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);

    bench_encrypt_sector(&mut group, &mut rng, &xts);
}

fn encryption_256(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("xts-128 aes-256 enc");

    let mut rng = rand::rng();

    let mut key: Array<u8, U64> = Array([0u8; 64]);
    rng.fill_bytes(&mut key);

    let (key_1, key_2) = key.split::<U32>();
    let cipher_1 = Aes256::new(&key_1);
    let cipher_2 = Aes256::new(&key_2);

    let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

    bench_encrypt_sector(&mut group, &mut rng, &xts);
}

criterion_group!(benches, encryption_128, encryption_256,);
criterion_main!(benches);
