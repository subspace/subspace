use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use x509_parser::prelude::FromDer;

#[cfg(test)]
use crate::Pallet as AutoId;

const SEED: u32 = 0;

#[benchmarks]
mod benchmarks {
    use super::*;
    use crate::utils::{algorithm_to_der, sign_preimage};

    fn register_auto_id<T: crate::Config>(issuer_id: Option<Identifier>) -> Identifier {
        let caller: T::AccountId = account("caller", 1, SEED);

        let auto_id_identifier = NextAutoIdIdentifier::<T>::get();

        if let Some(issuer_id) = issuer_id {
            let leaf_cert = include_bytes!("../res/leaf.cert.der").to_vec();
            let (_, cert) =
                x509_parser::certificate::X509Certificate::from_der(&leaf_cert).unwrap();
            Pallet::<T>::register_auto_id(
                RawOrigin::Signed(caller).into(),
                RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
                    issuer_id,
                    certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                    signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                    signature: cert.signature_value.as_ref().to_vec(),
                }),
            )
            .unwrap();
        } else {
            let issuer_cert = include_bytes!("../res/issuer.cert.der").to_vec();
            let (_, cert) =
                x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
            Pallet::<T>::register_auto_id(
                RawOrigin::Signed(caller).into(),
                RegisterAutoId::X509(RegisterAutoIdX509::Root {
                    certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                    signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                    signature: cert.signature_value.as_ref().to_vec(),
                }),
            )
            .unwrap();
        }

        assert_eq!(NextAutoIdIdentifier::<T>::get(), auto_id_identifier + 1);
        auto_id_identifier
    }

    #[benchmark]
    fn register_auto_id_root() {
        let issuer_cert = include_bytes!("../res/issuer.cert.der").to_vec();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
        let auto_id_identifier = NextAutoIdIdentifier::<T>::get();

        let caller: T::AccountId = account("caller", 1, SEED);

        #[extrinsic_call]
        Pallet::<T>::register_auto_id(
            RawOrigin::Signed(caller),
            RegisterAutoId::X509(RegisterAutoIdX509::Root {
                certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                signature: cert.signature_value.as_ref().to_vec(),
            }),
        );

        assert_eq!(NextAutoIdIdentifier::<T>::get(), auto_id_identifier + 1);
    }

    #[benchmark]
    fn register_auto_id_leaf() {
        let issuer_auto_id = register_auto_id::<T>(None);

        let cert = include_bytes!("../res/leaf.cert.der").to_vec();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&cert).unwrap();
        let caller: T::AccountId = account("caller", 1, SEED);

        #[extrinsic_call]
        Pallet::<T>::register_auto_id(
            RawOrigin::Signed(caller),
            RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
                issuer_id: issuer_auto_id,
                certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                signature: cert.signature_value.as_ref().to_vec(),
            }),
        );

        assert_eq!(NextAutoIdIdentifier::<T>::get(), issuer_auto_id + 1);
    }

    #[benchmark]
    fn revoke_certificate() {
        let issuer_auto_id = register_auto_id::<T>(None);
        let caller: T::AccountId = account("caller", 1, SEED);

        let auto_id = AutoIds::<T>::get(issuer_auto_id).unwrap();

        assert!(!auto_id.certificate.is_revoked());
        let signing_data = CertificateAction {
            id: issuer_auto_id,
            nonce: auto_id.certificate.nonce(),
            action_type: CertificateActionType::RevokeCertificate,
        };
        let signature = sign_preimage(signing_data.encode());

        let leaf_auto_id = NextAutoIdIdentifier::<T>::get();

        register_auto_id::<T>(Some(issuer_auto_id));

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), leaf_auto_id, signature);

        assert_eq!(NextAutoIdIdentifier::<T>::get(), leaf_auto_id + 1);
    }

    #[benchmark]
    fn deactivate_auto_id() {
        let issuer_auto_id = register_auto_id::<T>(None);
        let caller: T::AccountId = account("caller", 1, SEED);

        let auto_id = AutoIds::<T>::get(issuer_auto_id).unwrap();

        let signing_data = CertificateAction {
            id: issuer_auto_id,
            nonce: auto_id.certificate.nonce(),
            action_type: CertificateActionType::DeactivateAutoId,
        };
        let signature = sign_preimage(signing_data.encode());

        let leaf_auto_id = NextAutoIdIdentifier::<T>::get();

        register_auto_id::<T>(Some(issuer_auto_id));

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), leaf_auto_id, signature);

        assert_eq!(NextAutoIdIdentifier::<T>::get(), leaf_auto_id + 1);
    }

    impl_benchmark_test_suite!(AutoId, crate::tests::new_test_ext(), crate::tests::Test);
}
