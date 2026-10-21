use omamori_proto::crypto::{self, Key, KeyPair};
#[path = "../support/vectors.rs"]
mod vectors;

#[test]
fn primitive_known_answers_and_constant_time_compare() {
    assert_eq!(
        vectors::hex(&crypto::sha256(&[b"a", b"bc"])),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // RFC 4231, test case 1, extended to a 32-byte key by HMAC's zero padding.
    let mut bytes = [0; 32];
    bytes[..20].fill(0x0b);
    assert_eq!(
        vectors::hex(&crypto::hmac_sha256(&Key::new(bytes), &[b"Hi There"])),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert!(crypto::constant_time_eq(&[1; 32], &[1; 32]));
    assert!(!crypto::constant_time_eq(&[1; 32], &[2; 32]));
    assert!(!crypto::constant_time_eq(&[1; 32], &[1; 31]));
    assert_eq!(format!("{:?}", Key::new([7; 32])), "Key([REDACTED])");
}

#[test]
fn invalid_ecdh_scalars_and_public_keys_fail() {
    assert!(KeyPair::from_scalar(&[0; 32]).is_err());
    assert!(KeyPair::from_scalar(&[255; 32]).is_err());
    let pair = KeyPair::from_scalar(&[1; 32]).unwrap();
    assert!(
        pair.derive_key(&[0; 65], &[0; 16], &[0; 16], &[0; 16])
            .is_err()
    );
    let mut invalid = [0; 65];
    invalid[0] = 4;
    assert!(
        pair.derive_key(&invalid, &[0; 16], &[0; 16], &[0; 16])
            .is_err()
    );
}

#[test]
fn committed_vectors_are_reproducible() {
    let expected = include_str!("../../../test-vectors/v1.json");
    assert_eq!(
        format!(
            "{}\n",
            serde_json::to_string_pretty(&vectors::generate()).unwrap()
        ),
        expected
    );
}
