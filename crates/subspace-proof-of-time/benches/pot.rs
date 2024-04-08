use core::num::NonZeroU32;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use methods::AES_VERIFY_ELF;
use rand::{thread_rng, Rng};
use risc0_zkvm::{default_prover, ExecutorEnv};
use subspace_core_primitives::PotSeed;
use subspace_proof_of_time::{prove, verify};

fn criterion_benchmark(c: &mut Criterion) {
    let mut seed = PotSeed::default();
    thread_rng().fill(seed.as_mut());
    // About 1s on 6.0 GHz Raptor Lake CPU (14900K)
    let pot_iterations = NonZeroU32::new(200_032_000).expect("Not zero; qed");

    c.bench_function("prove", |b| {
        b.iter(|| {
            black_box(prove(black_box(seed), black_box(pot_iterations))).unwrap();
        })
    });

    let checkpoints = prove(seed, pot_iterations).unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| {
            black_box(verify(
                black_box(seed),
                black_box(pot_iterations),
                black_box(&*checkpoints),
            ))
            .unwrap();
        })
    });

    let prover = default_prover();

    c.bench_function("zk", |b| {
        b.iter(|| {
            let env = ExecutorEnv::builder()
                .write(&*seed)
                .unwrap()
                .write(&*seed.key())
                .unwrap()
                .write(&100u32)
                .unwrap()
                .build()
                .unwrap();

            let receipt = prover.prove(black_box(env), AES_VERIFY_ELF).unwrap();
            assert!(black_box(receipt.receipt.journal.decode().unwrap()));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
