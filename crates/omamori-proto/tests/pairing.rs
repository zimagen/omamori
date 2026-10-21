mod common;
use common::Rng;
use omamori_proto::{Output, PairFailure, crypto, host, watch, wire::Message};

fn start() -> (host::Session, watch::Session, Rng, Vec<u8>, Vec<u8>) {
    let mut rng = Rng(12345);
    let mut host = host::Session::pairing([1; 16], "PC 🖥");
    let (watch, commit) = watch::Session::pairing("Venu ⌚", &mut rng);
    let host_message = host.receive(&commit.messages[0], &mut rng).unwrap();
    (
        host,
        watch,
        rng,
        commit.messages[0].clone(),
        host_message.messages[0].clone(),
    )
}

fn exchange() -> (host::Session, watch::Session, Rng) {
    let (mut host, mut watch, mut rng, _, host_message) = start();
    let reveal = watch.receive(&host_message).unwrap();
    let code = host.receive(&reveal.messages[0], &mut rng).unwrap();
    match (&code.events[0], &reveal.events[0]) {
        (host::Event::PairCode(h, name), watch::Event::PairCode(w, host_name)) => {
            assert_eq!(h, w);
            assert_eq!(h.len(), 6);
            assert!(h.bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(name, "Venu ⌚");
            assert_eq!(host_name, "PC 🖥");
        }
        _ => panic!("missing SAS"),
    }
    (host, watch, rng)
}

fn assert_host_failed(out: &Output<host::Event>, reason: PairFailure) {
    assert!(matches!(out.events.as_slice(), [host::Event::PairFailed(r)] if *r == reason));
    assert_eq!(
        Message::decode(&out.messages[0]).unwrap(),
        Message::PairResult {
            accepted: false,
            mac: [0; 32]
        }
    );
}

#[test]
fn pairing_equal_sas_and_keys_both_confirmation_orders() {
    for host_first in [false, true] {
        let (mut host, mut watch, mut rng) = exchange();
        let confirm = watch.confirm_pairing(true).unwrap();
        let result = if host_first {
            assert!(host.confirm_pairing(true).unwrap().events.is_empty());
            host.receive(&confirm.messages[0], &mut rng).unwrap()
        } else {
            assert!(
                host.receive(&confirm.messages[0], &mut rng)
                    .unwrap()
                    .events
                    .is_empty()
            );
            host.confirm_pairing(true).unwrap()
        };
        let paired = watch.receive(&result.messages[0]).unwrap();
        match (&result.events[0], &paired.events[0]) {
            (
                host::Event::Paired { key: h, watch_name },
                watch::Event::Paired {
                    key: w,
                    host_id,
                    host_name,
                },
            ) => {
                assert!(crypto::constant_time_eq(h.as_bytes(), w.as_bytes()));
                assert_eq!(watch_name, "Venu ⌚");
                assert_eq!(host_name, "PC 🖥");
                assert_eq!(*host_id, [1; 16]);
            }
            _ => panic!("missing paired events"),
        }
        assert!(host.is_closed());
        assert!(watch.is_closed());
        assert!(host.confirm_pairing(true).is_err());
        assert!(watch.confirm_pairing(true).is_err());
    }
}

#[test]
fn either_side_rejects_nothing_stored() {
    let (mut host, mut watch, _) = exchange();
    let result = host.confirm_pairing(false).unwrap();
    assert_host_failed(&result, PairFailure::Rejected);
    let failed = watch.receive(&result.messages[0]).unwrap();
    assert!(matches!(
        failed.events.as_slice(),
        [watch::Event::PairFailed(PairFailure::Rejected)]
    ));

    let (mut host, mut watch, mut rng) = exchange();
    host.confirm_pairing(true).unwrap();
    let confirm = watch.confirm_pairing(false).unwrap();
    assert!(matches!(
        confirm.events.as_slice(),
        [watch::Event::PairFailed(PairFailure::Rejected)]
    ));
    let result = host.receive(&confirm.messages[0], &mut rng).unwrap();
    assert_host_failed(&result, PairFailure::Rejected);
    assert!(watch.is_closed());
    assert!(host.is_closed());
}

#[test]
fn commitment_mismatch_and_tampered_reveal_fields() {
    for offset in [2, 67] {
        let (mut host, mut watch, mut rng, _, host_message) = start();
        let mut reveal = watch.receive(&host_message).unwrap().messages.remove(0);
        reveal[offset] ^= 1;
        let failed = host.receive(&reveal, &mut rng).unwrap();
        assert_host_failed(&failed, PairFailure::Commitment);
        assert!(host.is_closed());
    }
}

#[test]
fn tampered_reveal_name_breaks_transcript_mac() {
    let (mut host, mut watch, mut rng, _, host_message) = start();
    let mut reveal = watch.receive(&host_message).unwrap().messages.remove(0);
    reveal[84] ^= 1; // first ASCII name byte
    host.receive(&reveal, &mut rng).unwrap();
    host.confirm_pairing(true).unwrap();
    let confirm = watch.confirm_pairing(true).unwrap();
    assert_host_failed(
        &host.receive(&confirm.messages[0], &mut rng).unwrap(),
        PairFailure::BadMac,
    );
}

#[test]
fn tampered_pair_host_nonce_name_and_public_key_fail() {
    for offset in [67, 100] {
        let (mut host, mut watch, mut rng, _, mut host_message) = start();
        host_message[offset] ^= 1;
        let reveal = watch.receive(&host_message).unwrap();
        host.receive(&reveal.messages[0], &mut rng).unwrap();
        host.confirm_pairing(true).unwrap();
        let confirm = watch.confirm_pairing(true).unwrap();
        assert_host_failed(
            &host.receive(&confirm.messages[0], &mut rng).unwrap(),
            PairFailure::BadMac,
        );
    }
    let (_, mut watch, _, _, mut host_message) = start();
    host_message[2] = 0; // non-SEC1 public key
    let out = watch.receive(&host_message).unwrap();
    assert!(matches!(
        out.events.as_slice(),
        [watch::Event::PairFailed(PairFailure::InvalidKey)]
    ));
}

#[test]
fn bad_watch_confirm_mac_and_bad_host_result_mac() {
    let (mut host, mut watch, mut rng) = exchange();
    host.confirm_pairing(true).unwrap();
    let mut confirm = watch.confirm_pairing(true).unwrap().messages.remove(0);
    confirm[3] ^= 1;
    assert_host_failed(
        &host.receive(&confirm, &mut rng).unwrap(),
        PairFailure::BadMac,
    );

    let (mut host, mut watch, mut rng) = exchange();
    host.confirm_pairing(true).unwrap();
    let confirm = watch.confirm_pairing(true).unwrap();
    let mut result = host
        .receive(&confirm.messages[0], &mut rng)
        .unwrap()
        .messages
        .remove(0);
    result[3] ^= 1;
    let out = watch.receive(&result).unwrap();
    assert!(matches!(
        out.events.as_slice(),
        [watch::Event::PairFailed(PairFailure::BadMac)]
    ));
}

#[test]
fn unexpected_or_malformed_pair_message_fails_closed() {
    let (mut host, mut watch, mut rng, _, _) = start();
    assert_host_failed(
        &host.receive(&[2, 0x10], &mut rng).unwrap(),
        PairFailure::Protocol,
    );
    let out = watch
        .receive(
            &Message::AuthHello {
                watch_nonce: [0; 16],
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        out.events.as_slice(),
        [watch::Event::PairFailed(PairFailure::Protocol)]
    ));
}
