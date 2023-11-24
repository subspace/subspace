//! Operator specific RPC implementation.

use domain_rpc_api::operator::{Error as OperatorRPCError, OperatorApiServer};
use jsonrpsee::core::{async_trait, RpcResult};
use sc_rpc_api::DenyUnsafe;
use sp_application_crypto::AppCrypto;
use sp_core::Bytes;
use sp_domains::OperatorPair;
use sp_keystore::KeystorePtr;

/// Operator API
pub struct Operator {
    /// The key store.
    keystore: KeystorePtr,
    /// Whether to deny unsafe calls
    deny_unsafe: DenyUnsafe,
}

impl Operator {
    /// Create new instance of Operator API.
    pub fn new(keystore: KeystorePtr, deny_unsafe: DenyUnsafe) -> Self {
        Operator {
            keystore,
            deny_unsafe,
        }
    }
}

#[async_trait]
impl OperatorApiServer for Operator {
    fn insert_key(&self, suri: String, public: Bytes) -> RpcResult<()> {
        self.deny_unsafe.check_if_safe()?;
        let key_type = OperatorPair::ID;
        self.keystore
            .insert(key_type, &suri, &public[..])
            .map_err(|_| OperatorRPCError::KeystoreUnavailable)?;
        Ok(())
    }

    fn generate_key(&self) -> RpcResult<Bytes> {
        self.deny_unsafe.check_if_safe()?;
        let key_type = OperatorPair::ID;
        let pubkey = self
            .keystore
            .sr25519_generate_new(key_type, None)
            .map_err(|_| OperatorRPCError::KeystoreUnavailable)?;
        Ok(pubkey.to_vec().into())
    }

    fn has_key(&self, public_key: Bytes) -> RpcResult<bool> {
        self.deny_unsafe.check_if_safe()?;
        let key_type = OperatorPair::ID;
        Ok(self.keystore.has_keys(&[(public_key.to_vec(), key_type)]))
    }
}

#[cfg(test)]
mod tests {
    use crate::operator::Operator;
    use domain_rpc_api::operator::OperatorApiServer;
    use jsonrpsee::types::EmptyServerParams;
    use sc_rpc_api::DenyUnsafe;
    use sp_core::crypto::Pair;
    use sp_core::Bytes;
    use sp_domains::OperatorPair;
    use sp_keystore::testing::MemoryKeystore;
    use std::sync::Arc;

    struct TestSetup {
        pub keystore: Arc<MemoryKeystore>,
    }

    impl Default for TestSetup {
        fn default() -> Self {
            let keystore = Arc::new(MemoryKeystore::new());
            TestSetup { keystore }
        }
    }

    impl TestSetup {
        fn operator(&self) -> Operator {
            Operator {
                keystore: self.keystore.clone(),
                deny_unsafe: DenyUnsafe::No,
            }
        }
    }

    #[tokio::test]
    async fn operator_should_insert_key() {
        let setup = TestSetup::default();
        let api = setup.operator().into_rpc();
        let suri = "//Alice";
        let keypair = OperatorPair::from_string(suri, None).unwrap();
        let params: (String, Bytes) = (
            suri.to_string(),
            keypair.public().into_inner().to_vec().into(),
        );
        api.call::<_, ()>("operator_insertKey", params)
            .await
            .unwrap();

        assert!(api
            .call::<Vec<Bytes>, bool>(
                "operator_hasKey",
                vec![keypair.public().into_inner().to_vec().into()],
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn operator_should_generate_key() {
        let setup = TestSetup::default();
        let api = setup.operator().into_rpc();
        let pubkey = api
            .call::<_, Bytes>("operator_generateKey", EmptyServerParams::new())
            .await
            .unwrap();

        assert!(api
            .call::<Vec<Bytes>, bool>("operator_hasKey", vec![pubkey],)
            .await
            .unwrap());
    }
}
