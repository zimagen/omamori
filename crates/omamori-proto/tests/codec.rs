mod common;
use common::{Rng, entry};
use omamori_proto::{
    framing::{self, Reassembler},
    wire::{self, Kind, Message},
};
use rand_core::Rng as _;

fn messages() -> Vec<Message> {
    vec![
        Message::AuthHello {
            watch_nonce: [1; 16],
        },
        Message::Approve {
            req_id: [2; 8],
            mac: [3; 32],
        },
        Message::PairCommit { commit: [4; 32] },
        Message::PairReveal {
            watch_pub: [5; 65],
            watch_nonce: [6; 16],
            watch_name: "⌚".into(),
        },
        Message::PairConfirm {
            accepted: false,
            mac: [7; 32],
        },
        Message::PairConfirm {
            accepted: true,
            mac: [7; 32],
        },
        Message::Pending {
            host_id: [8; 16],
            host_name: "PC".into(),
            more: false,
            entries: vec![
                entry(1, Kind::Lock, false, 0),
                entry(2, Kind::Sudo, true, u16::MAX),
            ],
            mac: [9; 32],
        },
        Message::Pending {
            host_id: [8; 16],
            host_name: "".into(),
            more: false,
            entries: vec![],
            mac: [9; 32],
        },
        Message::Result {
            req_id: [10; 8],
            status: 0,
            mac: [11; 32],
        },
        Message::Result {
            req_id: [10; 8],
            status: 1,
            mac: [11; 32],
        },
        Message::Result {
            req_id: [10; 8],
            status: 2,
            mac: [11; 32],
        },
        Message::PairHost {
            host_pub: [12; 65],
            host_nonce: [13; 16],
            host_id: [14; 16],
            host_name: "主機".into(),
        },
        Message::PairResult {
            accepted: true,
            mac: [15; 32],
        },
        Message::PairResult {
            accepted: false,
            mac: [0; 32],
        },
        Message::Error { code: 1 },
        Message::Error { code: 2 },
        Message::Error { code: 3 },
        Message::Error { code: 4 },
    ]
}

#[test]
fn every_message_round_trips_and_rejects_all_truncations_and_trailing_bytes() {
    for message in messages() {
        let bytes = message.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        for len in 0..bytes.len() {
            assert!(
                Message::decode(&bytes[..len]).is_err(),
                "{message:?} truncated at {len}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(Message::decode(&trailing), Err(wire::Error::Trailing));
        let mut version = bytes;
        version[0] = 2;
        assert_eq!(Message::decode(&version), Err(wire::Error::Version));
    }
}

#[test]
fn unknown_types_invalid_utf8_boolean_kind_flags_and_status_are_errors() {
    assert_eq!(Message::decode(&[1, 0x42]), Err(wire::Error::Type));
    let mut reveal = Message::PairReveal {
        watch_pub: [4; 65],
        watch_nonce: [1; 16],
        watch_name: "a".into(),
    }
    .encode()
    .unwrap();
    *reveal.last_mut().unwrap() = 0xff;
    assert_eq!(Message::decode(&reveal), Err(wire::Error::Utf8));
    let mut confirm = Message::PairConfirm {
        accepted: true,
        mac: [0; 32],
    }
    .encode()
    .unwrap();
    confirm[2] = 2;
    assert_eq!(Message::decode(&confirm), Err(wire::Error::Value));
    let pending = Message::Pending {
        host_id: [0; 16],
        host_name: "".into(),
        more: false,
        entries: vec![entry(1, Kind::Lock, false, 1)],
        mac: [0; 32],
    }
    .encode()
    .unwrap();
    for offset in [29, 30] {
        let mut invalid = pending.clone();
        invalid[offset] = 3;
        assert_eq!(Message::decode(&invalid), Err(wire::Error::Value));
    }
    let mut result = Message::Result {
        req_id: [0; 8],
        status: 0,
        mac: [0; 32],
    }
    .encode()
    .unwrap();
    result[10] = 3;
    assert_eq!(Message::decode(&result), Err(wire::Error::Value));
    assert!(
        Message::Result {
            req_id: [0; 8],
            status: 3,
            mac: [0; 32]
        }
        .encode()
        .is_err()
    );
    assert!(Message::Error { code: 5 }.encode().is_err());
}

#[test]
fn strings_truncate_on_utf8_boundary_and_oversize_messages_fail() {
    for prefix_len in 251..=256 {
        let value = format!("{}⌚🦀", "x".repeat(prefix_len));
        let shortened = wire::truncate_str(&value);
        assert!(shortened.len() <= 255);
        assert!(value.starts_with(shortened));
        let message = Message::PairReveal {
            watch_pub: [0; 65],
            watch_nonce: [0; 16],
            watch_name: value,
        };
        let bytes = message.encode().unwrap();
        assert_eq!(usize::from(bytes[83]), bytes.len() - 84);
        assert!(Message::decode(&bytes).is_ok());
    }
    let oversized = Message::Pending {
        host_id: [0; 16],
        host_name: "x".repeat(255),
        more: false,
        entries: vec![
            wire::Entry {
                title: "x".repeat(255),
                detail: "x".repeat(255),
                ..entry(1, Kind::Lock, false, 1)
            };
            4
        ],
        mac: [0; 32],
    };
    assert_eq!(oversized.encode(), Err(wire::Error::Oversize));
    assert_eq!(Message::decode(&[0; 1025]), Err(wire::Error::Oversize));
}

#[test]
fn framing_round_trip_boundaries_sequence_wrap_and_multiple_messages() {
    for size in [2, 20, 244] {
        let mut receiver = Reassembler::new(size).unwrap();
        for len in [0, 1, 18, 19, 20, 127, 128, 129, 1023, 1024] {
            let message: Vec<_> = (0..len).map(|i| i as u8).collect();
            let chunks = framing::chunk(&message, size).unwrap();
            let count = chunks.len();
            for (i, chunk) in chunks.into_iter().enumerate() {
                assert!(chunk.len() <= size);
                assert_eq!(chunk[0] & 0x7f, (i % 128) as u8);
                let out = receiver.receive(&chunk).unwrap();
                if i + 1 == count {
                    assert_eq!(out, Some(message.clone()));
                } else {
                    assert_eq!(out, None);
                }
            }
        }
    }
}

#[test]
fn framing_rejects_out_of_order_oversize_and_invalid_chunks_until_reset() {
    assert!(framing::chunk(&[], 1).is_err());
    assert!(Reassembler::new(1).is_err());
    assert!(framing::chunk(&[0; 1025], 20).is_err());
    let mut receiver = Reassembler::new(20).unwrap();
    assert_eq!(receiver.receive(&[1, 42]), Err(framing::Error::Sequence));
    assert!(receiver.receive(&[0x80, 42]).is_err());
    receiver.reset();
    assert_eq!(receiver.receive(&[0x80, 42]), Ok(Some(vec![42])));
    assert_eq!(receiver.receive(&[]), Err(framing::Error::EmptyChunk));
    receiver.reset();
    assert_eq!(receiver.receive(&[0; 21]), Err(framing::Error::ChunkSize));
    receiver.reset();
    for seq in 0..53 {
        let mut chunk = [0; 20];
        chunk[0] = seq;
        assert_eq!(receiver.receive(&chunk), Ok(None));
    }
    let mut last = [0; 20];
    last[0] = 53 | 0x80;
    assert_eq!(receiver.receive(&last), Err(framing::Error::Oversize));
}

#[test]
fn seeded_random_decoders_and_mutated_valid_messages_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut receiver = Reassembler::new(244).unwrap();
    for iteration in 0..20_000 {
        let len = (rng.next_u32() % 1100) as usize;
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        let _ = Message::decode(&bytes);
        let _ = receiver.receive(&bytes);
        if iteration % 8 == 0 {
            receiver.reset();
        }
    }
    for message in messages() {
        let original = message.encode().unwrap();
        for _ in 0..500 {
            let mut bytes = original.clone();
            let index = rng.next_u32() as usize % bytes.len();
            bytes[index] = rng.next_u32() as u8;
            if let Ok(decoded) = Message::decode(&bytes) {
                assert_eq!(decoded.encode().unwrap(), bytes);
            }
        }
    }
}

#[test]
fn pending_rejects_reserved_more_values_and_overlong_wire_fields() {
    let pending = Message::Pending {
        host_id: [0; 16],
        host_name: String::new(),
        more: true,
        entries: vec![wire::Entry {
            title: "t".repeat(48),
            detail: "d".repeat(160),
            ..entry(1, Kind::Sudo, true, 0)
        }],
        mac: [0; 32],
    }
    .encode()
    .unwrap();
    assert!(matches!(
        Message::decode(&pending).unwrap(),
        Message::Pending { more: true, .. }
    ));
    let mut invalid = pending.clone();
    invalid[19] = 2;
    assert_eq!(Message::decode(&invalid), Err(wire::Error::Value));
    for (offset, length) in [(33, 48), (82, 160)] {
        let mut invalid = pending.clone();
        invalid[offset] = length + 1;
        invalid.insert(offset + 1, b'x');
        assert_eq!(Message::decode(&invalid), Err(wire::Error::Value));
    }
}
