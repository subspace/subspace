#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let seed: [u8; 16] = env::read();
    let key: [u8; 16] = env::read();
    let checkpoint_iterations: u32 = env::read();

    let result = verify_sequential(seed, key, checkpoint_iterations);

    // write public output to the journal
    env::commit(&result);
}

extern crate alloc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// Verifies the AES based proof sequentially.
///
/// Panics if `checkpoint_iterations` is not a multiple of `2`.
#[inline(always)]
pub(crate) fn verify_sequential(seed: [u8; 16], key: [u8; 16], checkpoint_iterations: u32) -> bool {
    // assert_eq!(checkpoint_iterations % 2, 0);

    let mut seed = GenericArray::from(seed);
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);

    for _ in 0..checkpoint_iterations {
        cipher.encrypt_block(&mut seed);
    }

    true
}

/// Verifies the AES based proof sequentially.
///
/// Panics if `checkpoint_iterations` is not a multiple of `2`.
#[inline(always)]
pub(crate) fn verify_sequential_soft(
    seed: [u8; 16],
    key: [u8; 16],
    checkpoint_iterations: u32,
) -> bool {
    use soft_aes::aes::aes_dec_block;

    let mut seed = copy_block_to_state(&seed);

    for _ in 0..checkpoint_iterations {
        aes_dec_block(&mut seed, &key);
    }

    true
}

fn copy_block_to_state(block: &[u8; 16]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            state[j][i] = block[i * 4 + j];
        }
    }

    state
}
