use super::*;
use pem::parse;
use ring::rand::SystemRandom;
use ring::signature::RsaKeyPair;
use x509_parser::der_parser::asn1_rs::{FromDer, ToDer};
use x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA;
use x509_parser::x509::AlgorithmIdentifier;

/// Converts Algorithm identifier to Der since x509 does not implement the ToDer :(.
#[cfg(any(test, feature = "runtime-benchmarks"))]
pub(crate) fn algorithm_to_der(algorithm_identifier: AlgorithmIdentifier) -> DerVec {
    let sequence_tag: u8 = 0x30;
    let sequence_content = {
        let mut temp = Vec::new();
        temp.extend(algorithm_identifier.algorithm.to_der_vec().unwrap());
        temp.extend(algorithm_identifier.parameters.to_der_vec().unwrap());
        temp
    };
    let encoded_sequence_length = {
        let content_length = sequence_content.len();
        if content_length > 127 {
            // This is long form length encoding
            let length_as_bytes = content_length.to_be_bytes();
            let mut encoded = Vec::with_capacity(length_as_bytes.len() + 1);
            // Set first bit to 1 and store number of length-bytes.
            encoded.push(0x80 | (length_as_bytes.len() as u8));
            encoded.extend_from_slice(&length_as_bytes);
            encoded
        } else {
            // The short form (single-byte length) can be used.
            vec![content_length as u8]
        }
    };

    let mut d = Vec::new();
    d.push(sequence_tag);
    d.extend(encoded_sequence_length);
    d.extend(sequence_content);
    let (_, derived) = AlgorithmIdentifier::from_der(&d).unwrap();
    assert_eq!(algorithm_identifier, derived);
    d.into()
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
pub(crate) fn sign_preimage(data: Vec<u8>) -> Signature {
    let priv_key_pem = include_str!("../res/private.issuer.pem");
    let priv_key_der = parse(priv_key_pem).unwrap().contents().to_vec();
    let rsa_key_pair = RsaKeyPair::from_pkcs8(&priv_key_der).unwrap();
    let mut signature = vec![0; rsa_key_pair.public().modulus_len()];
    let rng = SystemRandom::new();
    rsa_key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            &data,
            &mut signature,
        )
        .unwrap();
    let algo = AlgorithmIdentifier {
        algorithm: OID_PKCS1_SHA256WITHRSA,
        parameters: None,
    };
    Signature {
        signature_algorithm: algorithm_to_der(algo),
        value: signature,
    }
}
