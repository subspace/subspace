//! AES Core Implementation
//!
//! This module provides core functionalities for the AES (Advanced Encryption
//! Standard) algorithm. It includes implementations for both encryption and
//! decryption processes along with the necessary auxiliary functions.
//!
//! The implementation follows a software-based approach, primarily utilizing
//! lookup tables for operations such as S-box transformations. While the method
//! ensures accuracy, it might not be optimized for high perfomance in terms of
//! speed and memory usage.
//!
//! # Disclaimer
//!
//! This implementation is provided "as is", without warranty of any kind,
//! express or implied. The author(s) or contributor(s) are not responsible for
//! any consequences arising from the use or misuse of this code. Users are
//! encouraged to understand and evaluate the suitability of this code for
//! their purposes, especially in critical or sensitive systems.
//!
//! # Features
//!
//! - Supports AES-128, AES-192, and AES-256 key sizes.
//! - Implements key expansion routine for generating round keys from the
//!   initial cipher key.
//! - Provides functions for each step of the AES algorithm, including:
//!     - `sub_bytes` and `inv_sub_bytes` for the SubBytes and InvSubBytes
//!        steps (byte substitution).
//!     - `shift_rows` and `inv_shift_rows` for the ShiftRows and InvShiftRows
//!        steps.
//!     - `mix_columns` and `inv_mix_columns` for the MixColumns and
//!        InvMixColumns steps.
//!     - `add_round_key` for the AddRoundKey step.
//! - Contains the main functions `aes_enc_block` and `aes_dec_block` for block
//!   encryption and decryption.
//!
//! # Usage
//!
//! This module is intended to be used as part of a larger AES implementation.
//! It handles the core operations of the AES algorithm but does not include
//! modes of operation like ECB, CBC, etc. Users of this module need to handle
//! padding, chaining, and other aspects relevant to their specific use case.
//!
//! # Examples
//!
//! Basic usage for encrypting and decrypting a single block for AES-128
//!
//! ```
//! use crate::soft_aes::aes::{aes_enc_block, aes_dec_block, AES_BLOCK_SIZE, AES_128_KEY_SIZE};
//!
//! // Test vectors for AES-128
//! let plaintext: [u8; AES_BLOCK_SIZE] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00,
//! ];
//! let key: [u8; AES_128_KEY_SIZE] = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
//!     0xee, 0xff,
//! ];
//! let expected_ciphertext: [u8; AES_BLOCK_SIZE] = [
//!     0xfd, 0xe4, 0xfb, 0xae, 0x4a, 0x09, 0xe0, 0x20, 0xef, 0xf7, 0x22, 0x96, 0x9f, 0x83,
//!     0x83, 0x2b,
//! ];
//!
//! // Perform AES-128 encryption
//! let ciphertext = aes_enc_block(&plaintext, &key).expect("Encryption failed");
//! assert_eq!(ciphertext, expected_ciphertext);
//!
//! // Perform AES-128 decryption
//! let decrypted = aes_dec_block(&ciphertext, &key).expect("Decryption failed");
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! # Notes
//! - The test vectors used in unit tests are sourced from
//!   https://www.cryptool.org/en/cto/aes-step-by-step.
//! - The implementation follows the principles outlined in "The Design of
//!   Rijndael: AES - The Advanced Encryption Standard" by Joan Daemen and
//!   Vincent Rijmen, Second Edition, 2020. However, some modifications have
//!   been made to adapt the algorithm to specific requirements.
//! - Notably, the round keys are stored and managed using a fixed byte buffer
//!   instead of a multi-dimensional array as traditionally specified.

// AES block size is fixed at 16 bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// AES key size constants define the key sizes used in the AES algorithm for
/// the three standard variations of AES.
pub const AES_128_KEY_SIZE: usize = 16;
pub const AES_192_KEY_SIZE: usize = 24;
pub const AES_256_KEY_SIZE: usize = 32;

// The number of columns comprising a state in AES.
const NB: usize = 4;

/// The S-box is a substitution box used in the SubBytes step of the AES
/// encryption process.
/// It's a fixed (non-key-dependent) table used in the byte substitution
/// transformation of the AES algorithm.
/// Each byte in the state array is replaced with its corresponding value in
/// the S-box.
/// This provides the non-linear transformation in the cipher, a critical
/// component for its security.
///
/// Note: These values are specific to AES algorithm and part of its standard
/// specification.
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The Inverse S-box used in the AES decryption algorithm.
const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// The round constant word array, RCON[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field
// GF(2^8)
// Note that i starts at 1, not 0).
const RCON: [u8; 255] = [
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A,
    0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
    0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF,
    0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC,
    0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,
    0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3,
    0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94,
    0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35,
    0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F,
    0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
    0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD,
    0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB,
];

/// `LOG_TABLE` is a lookup table used to perform multiplications in GF(256).
/// Each element in this table represents the logarithm to the base generator
/// of the index. For example, LOG_TABLE[x] gives the power of the generator
/// that equals 'x' in the field.
/// This table is used in conjunction with the Algotable to perform finite field
/// multiplications.
/// This specific representation uses hexadecimal literals for clarity and
/// direct correspondence with their use in the AES algorithm.
const LOG_TABLE: [u8; 256] = [
    0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
    0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
    0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
    0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
    0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
    0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
    0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
    0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
    0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
    0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
    0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
    0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
    0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
    0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
];

/// `ALOG_TABLE` (antilog table) is a lookup table used for exponentiation in
/// GF(256).
/// Each element in this table represents the result of raising the generator
/// to an exponent equal to the index.
/// For example, ALOG_TABLE[x] gives the result of the generator raised to the
/// power of 'x' in the field.
/// This table is utilized for multiplying elements in the field by performing
/// exponentiation and logarithm operations,
/// The hexadecimal representation is used for direct usage in AES computations
/// and clarity of the finite field concepts.
const ALOG_TABLE: [u8; 256] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
];

/// Multiply two elements of GF(256).
///
/// This function is required for MixColumns and InvMixColumns steps in the AES
/// encryption and decryption process. It uses precomputed log and antilog
/// tables to perform the multiplication in the finite field.
///
/// Parameters:
///     a: u8 - The first element to multiply, represented as a byte.
///     b: u8 - The second element to multiply, represented as a byte.
///
/// Returns:
///     The product of the two elements in GF(256).
fn mul(a: u8, b: u8) -> u8 {
    if a != 0 && b != 0 {
        let log_a = LOG_TABLE[a as usize] as usize;
        let log_b = LOG_TABLE[b as usize] as usize;
        let log_sum = (log_a + log_b) % 255; // Modulo 255 to keep within bounds
        ALOG_TABLE[log_sum]
    } else {
        0
    }
}

/// Expand an AES key into a buffer of round keys.
///
/// This function takes an initial key and expands it into a series of round
/// keys, which are used in each round of the AES encryption/decryption process.
/// The expanded keys are stored in a single contiguous byte buffer, as opposed
/// to the more common approach of organizing them into an array of arrays,
/// where each sub-array represents a round key.
///
/// # Parameters
///
/// * `key`: A slice containing the initial AES key. Its length can be either
///          16, 24, or 32 bytes, corresponding to AES-128, AES-192, and
///          AES-256, respectively.
/// * `nk`: The number of 4-byte words in the original key. This is 4 for
///         AES-128, 6 for AES-192, and 8 for AES-256.
/// * `nr`: The number of rounds in the AES cipher, which depends on the key
///         size. This is 10 for AES-128, 12 for AES-192, and 14 for AES-256.
///
/// # Returns
///
/// A `[u8; 240]` array containing the expanded keys. This size accommodates
/// the largest key expansion (AES-256), which requires 15 round keys of 16
/// bytes each.
///
/// # Note
///
/// The function works directly on a byte buffer, rather than using a
/// `(MAX_ROUNDS+1)x4x4` array as traditionally specified in AES documentation.
/// Each round key is a sequence of 16 bytes within this buffer. The
/// organization of round keys in a single buffer can be more efficient for
/// certain implementations, as it avoids the overhead of multi-dimensional
/// array indexing.
fn expand_key(key: &[u8], nk: usize, nr: usize) -> [u8; 240] {
    let mut expanded_key = [0u8; 240]; // Fixed buffer for expanded key
    let mut temp = [0u8; 4]; // Temporary storage for key schedule

    // Copy the initial key as the first round key
    for i in 0..nk {
        expanded_key[i * 4..(i + 1) * 4].copy_from_slice(&key[i * 4..(i + 1) * 4]);
    }

    let mut i = nk; // Initialize `i` to number of words in the original key

    while i < NB * (nr + 1) {
        // Load the last word from the previous round key into `temp`
        for j in 0..4 {
            temp[j] = expanded_key[(i - 1) * 4 + j];
        }

        if i % nk == 0 {
            // Perform the RotWord operation for the first word in each new key
            let k = temp[0];
            temp.rotate_left(1); // Rotate the 4 bytes of the word to the left
            temp[3] = k;

            // SubWord operation: Substitute each byte in `temp` using the S-Box
            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }

            // XOR the first byte of `temp` with the round constant (RCON)
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // For AES-256, apply SubWord operation every fourth word
            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }
        }

        // Generate the next word of the round key
        for j in 0..4 {
            expanded_key[i * 4 + j] = expanded_key[(i - nk) * 4 + j] ^ temp[j];
        }
        i += 1;
    }
    expanded_key
}

/// Add a round key to the state using an XOR operation.
///
/// This function is a transformation in the cipher and inverse cipher where
/// the round key is combined with the state.
///
/// # Parameters
///
/// * `round`: The current round number.
/// * `state`: The current state of the cipher, represented as a mut 2D array.
/// * `expanded_key`: The expanded key buffer containing all round keys.
///
/// # Note
///
/// The state is modified in place by applying the XOR operation with the
/// corresponding round key from the expanded key buffer.
fn add_round_key(round: usize, state: &mut [[u8; 4]; 4], expanded_key: &[u8; 240]) {
    for i in 0..4 {
        for j in 0..4 {
            state[j][i] ^= expanded_key[round * NB * 4 + i * NB + j];
        }
    }
}

// /// Perform the SubBytes tranformation in the AES encryption algorithm.
// ///
// /// This function is a part of the AES encryption process where each byte
// /// in the state array is replaced with its corresponding value in the S-box.
// /// This substitution provides the non-linear transformation in the cipher.
// ///
// /// # Parameters
// ///
// /// * `state`: The current state of the cipher, represented as a mut 2D array.
// ///
// /// # Note
// ///
// /// The state is modified in place with the values from the S-box.
// fn sub_bytes(state: &mut [[u8; 4]; 4]) {
//     for i in 0..4 {
//         for j in 0..4 {
//             state[i][j] = S_BOX[state[i][j] as usize];
//         }
//     }
// }

/// Perform the InvSubBytes (Inverse SubBytes) transformation in the AES
/// decryption algorithm
///
/// This function is part of the AES decryption process where each byte
/// in the state array is replaced with its corresponding value in the inverse
/// S-box. This step reverses the non-linear transformation applied during
/// the encryption process.
///
/// # Parameters
///
/// * `state`: The current state of the cipher, represented as a mut 2D array.
///
/// # Note
///
/// The state is modified in place with the values from the inverse S-box.
fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = INV_S_BOX[state[i][j] as usize];
        }
    }
}

// /// Perform the ShiftRows transformation for AES encryption.
// ///
// /// This function cyclically shifts the rows of the state matrix to the left.
// /// Each row is shifted by a different offset depending on its index.
// ///
// /// # Parameters
// ///
// /// * `state`: The current state of the cipher, represented as a mut 2D array.
// ///
// /// # Note
// ///
// /// The state is modified in place with each row shifted accordingly.
// fn shift_rows(state: &mut [[u8; 4]; 4]) {
//     // Rotate the second row 1 column to the left
//     let temp = state[1][0];
//     state[1][0] = state[1][1];
//     state[1][1] = state[1][2];
//     state[1][2] = state[1][3];
//     state[1][3] = temp;
//
//     // Rotate the third row 2 columns to the left
//     let temp = state[2][0];
//     state[2][0] = state[2][2];
//     state[2][2] = temp;
//
//     let temp = state[2][1];
//     state[2][1] = state[2][3];
//     state[2][3] = temp;
//
//     // Rotate the fourth row 3 columns to the left
//     let temp = state[3][0];
//     state[3][0] = state[3][3];
//     state[3][3] = state[3][2];
//     state[3][2] = state[3][1];
//     state[3][1] = temp;
// }

/// Perform the InvShiftRows transformation for AES decryption.
///
/// This function cyclically shifts the rows of the state matrix to the right.
/// Each row is shifted by a different offset depending on its index.
///
/// # Parameters
///
/// * `state`: The current state of the cipher, represented as a mut 2D array.
///
/// # Note
///
/// The state is modified in place with each row shifted accordingly.
fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    // Rotate first row 1 columns to right
    let temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Rotate second row 2 columns to right
    let temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    let temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Rotate third row 3 columns to right
    let temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// /// Perform the MixColumns transformation for AES encryption
// ///
// /// This function mixes the columns of the state matrix. Each column is
// /// transformed using a fixed polynomial over GF(256).
// ///
// /// # Parameters
// ///
// /// * `state`: The current state of the cipher, represented as a mut 2D array.
// ///
// /// # Note
// ///
// /// The state is modified in place with each column mixed accordingly.
// fn mix_columns(state: &mut [[u8; 4]; 4]) {
//     for i in 0..4 {
//         // Iterate over each column
//         let t = state[0][i];
//         let tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
//
//         let mut tm = state[0][i] ^ state[1][i];
//         tm = mul(tm, 2);
//         state[0][i] ^= tm ^ tmp;
//
//         tm = state[1][i] ^ state[2][i];
//         tm = mul(tm, 2);
//         state[1][i] ^= tm ^ tmp;
//
//         tm = state[2][i] ^ state[3][i];
//         tm = mul(tm, 2);
//         state[2][i] ^= tm ^ tmp;
//
//         tm = state[3][i] ^ t;
//         tm = mul(tm, 2);
//         state[3][i] ^= tm ^ tmp;
//     }
// }

/// Perform the InvMixColuns transformation for the AES decryption.
///
/// This function reverses the mixing of columns applied during the encryption.
/// Each column is transformed using a fixed polynomial over GF(256) that is
/// the inverse of the polynomial used in the encryption process.
///
/// # Parameters
///
/// * `state`: The current state of the cipher, represented as a mut 2D array.
///
/// # Note
///
/// The state is modified in place with each column mixed accordingly.
fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        // Save original state for column i
        let a = state[0][i];
        let b = state[1][i];
        let c = state[2][i];
        let d = state[3][i];

        // Perform the inverse mix column operation on each element of the column
        state[0][i] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c, 0x0d) ^ mul(d, 0x09);
        state[1][i] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c, 0x0b) ^ mul(d, 0x0d);
        state[2][i] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c, 0x0e) ^ mul(d, 0x0b);
        state[3][i] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c, 0x09) ^ mul(d, 0x0e);
    }
}

/// Copy a 16-byte block into a 4x4 state array.
///
/// # Parameters
///
/// * `block`: The input block, represented as a 16-byte array.
///
/// # Returns
///
/// A 4x4 state array filled with data from the block.
fn copy_block_to_state(block: &[u8; AES_BLOCK_SIZE]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            state[j][i] = block[i * 4 + j];
        }
    }

    state
}

/// Copy a 4x4 state array into a 16-byte block.
///
/// # Parameters
///
/// * `state`: The 4x4 state array.
///
/// # Returns
///
/// A 16-byte array representing the block.
fn copy_state_to_block(state: &[[u8; 4]; 4]) -> [u8; AES_BLOCK_SIZE] {
    let mut block = [0u8; AES_BLOCK_SIZE];

    for i in 0..4 {
        for j in 0..4 {
            block[i * 4 + j] = state[j][i];
        }
    }

    block
}

/// Calculate the number of 32-bit words in the key and the number of
/// encryption rounds based on the key length for AES encryption.
///
/// # Parameters
///
/// * `key_length_bytes`: The length of the key in bytes (16, 24, or 32).
///
/// # Returns
///
/// A tuple containing the number of 32-bit words in the key and the number of
/// encryption rounds.
///
/// # Panics
///
/// Panics if the key length is not one of the valid AES key lengths (128, 192,
/// or 256 bits).
fn calculate_parameters(key_length_bytes: usize) -> (usize, usize) {
    let words_in_key = key_length_bytes / 4; // 1 word = 4 bytes
    let encryption_rounds = match words_in_key {
        4 => 10, // 128-bit key
        6 => 12, // 192-bit key
        8 => 14, // 256-bit key
        _ => panic!(
            "AES CORE PANIC: Invalid AES key length: {}",
            key_length_bytes
        ),
    };

    (words_in_key, encryption_rounds)
}

/// Validate the key length for AES encryption or decryption.
///
/// This function checks if the provided key lengths is suitable for AES. It
/// must be one of the standard AES key sizes: 128 bits (16 bytes), 192 bits
/// (24 bytes), or 256 bits (32 bytes).
///
/// # Parameters
///
/// * `key_len`: Length of the cipher key in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the block and key are of valid lengths.
/// * `Err(Box<dyn Error>)` - If the key length is invalid.
fn validate_key_len(key_len: usize) -> Result<(), ()> {
    match key_len {
        AES_128_KEY_SIZE | AES_192_KEY_SIZE | AES_256_KEY_SIZE => Ok(()),
        _ => Err(()),
    }
}

// /// Encrypt a single block using the AES algorithm.
// ///
// /// This function handles AES encryption for a single block of data using the
// /// specified key. It supports key sizes for AES-128, AES-192, and AES-256,
// /// which are determined by the length of the key provided.
// ///
// /// # Parameters
// ///
// /// * `block`: A reference to a 16-byte array representing the plaintext block
// ///            to be encrypted.
// /// * `key`: A reference to a byte slice representing the encryption key. The
// ///          length of this slice determines the key size: 16 bytes for AES-128,
// ///          24 bytes for AES-192, and 32 bytes for AES-256.
// ///
// /// # Returns
// ///
// /// * `Ok([u8; AES_BLOCK_SIZE])` - A 16-byte array representing the encrypted
// ///    ciphertext block.
// /// * `Err(Box<dyn Error>)` - If the key length is invalid.
// ///
// /// # Errors
// ///
// /// This function will return an error if:
// /// - The key length is not one of the valid AES key sizes (16, 24, or 32 bytes).
// pub fn aes_enc_block(
//     block: &[u8; AES_BLOCK_SIZE],
//     key: &[u8],
// ) -> Result<[u8; AES_BLOCK_SIZE], Box<dyn Error>> {
//     let key_len = key.len();
//
//     validate_key_len(key_len)?;
//
//     let (nk, nr) = calculate_parameters(key_len);
//
//     let mut state = copy_block_to_state(block);
//
//     let expanded_key = expand_key(key, nk, nr);
//
//     // Add the first round key to the state before starting the rounds
//     add_round_key(0, &mut state, &expanded_key);
//
//     // Main rounds
//     for round in 1..nr {
//         sub_bytes(&mut state);
//         shift_rows(&mut state);
//         mix_columns(&mut state);
//         add_round_key(round, &mut state, &expanded_key);
//     }
//
//     // Final round (without mix_columns)
//     sub_bytes(&mut state);
//     shift_rows(&mut state);
//     add_round_key(nr, &mut state, &expanded_key);
//
//     Ok(copy_state_to_block(&state))
// }

/// Decrypt a single block using the AES algorithm.
///
/// This function handles AES decryption for a single block of ciphertext using
/// the specified key. It supports key sizes for AES-128, AES-192, and AES-256,
/// which are determined by the length of the key provided.
///
/// # Parameters
///
/// * `ciphertext`: A reference to a 16-byte array representing the encrypted
///                 block to be decrypted.
/// * `key`: A reference to a byte slice representing the decryption key. The
///          length of this slice determines the key size: 16 bytes for AES-128,
///          24 bytes for AES-192, and 32 bytes for AES-256.
///
/// # Returns
///
/// * `Ok([u8; AES_BLOCK_SIZE])` - A 16-byte array representing the decrypted
///    plaintext block.
/// * `Err(Box<dyn Error>)` - If the key length is invalid.
///
/// # Errors
///
/// This function will return an error if:
/// - The key length is not one of the valid AES key sizes (16, 24, or 32 bytes).
pub fn aes_dec_block(ciphertext: &mut [[u8; 4]; 4], key: &[u8; AES_BLOCK_SIZE]) {
    // let key_len = key.len();

    // validate_key_len(key_len)?;

    let (nk, nr) = (4, 10);

    let expanded_key = expand_key(key, nk, nr);

    // Add the last round key to the state before starting the rounds
    add_round_key(nr, ciphertext, &expanded_key);

    // Main rounds
    for round in (1..nr).rev() {
        inv_shift_rows(ciphertext);
        inv_sub_bytes(ciphertext);
        add_round_key(round, ciphertext, &expanded_key);
        inv_mix_columns(ciphertext);
    }

    // Final round (without inv_mix_columns)
    inv_shift_rows(ciphertext);
    inv_sub_bytes(ciphertext);
    add_round_key(0, ciphertext, &expanded_key);
}
