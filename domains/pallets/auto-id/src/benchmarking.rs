use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use x509_parser::prelude::FromDer;

#[cfg(test)]
use crate::Pallet as AutoId;

#[benchmarks]
mod benchmarks {
    use super::*;
    use crate::algorithm_to_der;

    #[benchmark]
    fn register_auto_id_root() {
        let issuer_cert = include_bytes!("../res/issuer.cert.der").to_vec();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
        let auto_id_identifier = NextAutoIdIdentifier::<T>::get();

        #[extrinsic_call]
        Pallet::<T>::register_auto_id(
            RawOrigin::Signed(1).into(),
            RegisterAutoId::X509(RegisterAutoIdX509::Root {
                certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                signature: cert.signature_value.as_ref().to_vec(),
            }),
        );

        assert_eq!(NextAutoIdIdentifier::<T>::get(), auto_id_identifier + 1);
    }

    // #[benchmark]
    // fn register_auto_id_leaf() {
    //     let cert = include_bytes!("../res/leaf.cert.der").to_vec();
    //     let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&cert).unwrap();
    //     let auto_id_identifier = NextAutoIdIdentifier::<T>::get();

    //     let issuer_auto_id = register_issuer_auto_id();

    //     #[extrinsic_call]
    //     Pallet::<T>::register_auto_id(
    //         RawOrigin::Signed(1).into(),
    //         RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
    //             issuer_id: issuer_auto_id,
    //             certificate: cert.tbs_certificate.as_ref().to_vec().into(),
    //             signature_algorithm: algorithm_to_der(cert.signature_algorithm),
    //             signature: cert.signature_value.as_ref().to_vec(),
    //         }),
    //     );

    //     assert_eq!(NextAutoIdIdentifier::<T>::get(), auto_id_identifier + 1);
    // }

    impl_benchmark_test_suite!(AutoId, crate::tests::new_test_ext(), crate::tests::Test);
}
