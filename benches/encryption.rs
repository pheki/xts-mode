#[macro_use]
extern crate criterion;

use xts_mode::{get_tweak_default, Xts128};

use aes::{cipher::generic_array::GenericArray, Aes128, Aes256};
use cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};
use rand::RngCore;

const BENCHED_SECTOR_SIZES: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];

fn bench_encrypt_sector<
    M: Measurement,
    R: RngCore,
    C: BlockEncrypt + BlockDecrypt + BlockCipher,
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
        group.bench_function(&format!("sector size {} B", size), |benchmark| {
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

    let mut rng = rand::thread_rng();

    let mut key = [0; 32];
    rng.fill_bytes(&mut key);

    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);

    bench_encrypt_sector(&mut group, &mut rng, &xts);
}

fn encryption_256(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("xts-128 aes-256 enc");

    let mut rng = rand::thread_rng();

    let mut key = [0; 64];
    rng.fill_bytes(&mut key);

    let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
    let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));

    let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

    bench_encrypt_sector(&mut group, &mut rng, &xts);
}

criterion_group!(benches, encryption_128, encryption_256,);
criterion_main!(benches);
