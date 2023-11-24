//! Operator specific RPC Api.

use jsonrpsee::core::{Error as JsonRpseeError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use sp_core::Bytes;

/// Operator RPC Api
#[rpc(client, server)]
pub trait OperatorApi {
    /// Insert a key into the keystore.
    #[method(name = "operator_insertKey")]
    fn insert_key(&self, suri: String, public: Bytes) -> RpcResult<()>;

    /// Generate new operator signing key pair and returns the corresponding public key.
    #[method(name = "operator_generateKey")]
    fn generate_key(&self) -> RpcResult<Bytes>;

    /// Checks if the keystore has private keys for the given public key.
    ///
    /// Returns `true` if a private key could be found.
    #[method(name = "operator_hasKey")]
    fn has_key(&self, public_key: Bytes) -> RpcResult<bool>;
}

/// Operator RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Some random issue with the key store. Shouldn't happen.
    #[error("The key store is unavailable")]
    KeystoreUnavailable,
}

impl From<Error> for JsonRpseeError {
    fn from(e: Error) -> Self {
        match e {
            Error::KeystoreUnavailable => {
                JsonRpseeError::Custom("Keystore not available".to_string())
            }
        }
    }
}
