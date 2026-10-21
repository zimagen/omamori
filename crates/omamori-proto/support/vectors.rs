use omamori_proto::{
    crypto::{self, KeyPair},
    framing,
    wire::{Entry, Kind, Message},
};
use p256::SecretKey;
use serde_json::{Value, json};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn generate() -> Value {
    let mut host_scalar = [0; 32];
    host_scalar[31] = 1;
    let mut watch_scalar = [0; 32];
    watch_scalar[31] = 2;
    let host = KeyPair::from_scalar(&host_scalar).unwrap();
    let watch = KeyPair::from_scalar(&watch_scalar).unwrap();
    let host_nonce = std::array::from_fn(|i| 0xa0 + i as u8);
    let watch_nonce = std::array::from_fn(|i| 0xb0 + i as u8);
    let host_id = std::array::from_fn(|i| 0xc0 + i as u8);
    let key = host
        .derive_key(&watch.public(), &host_nonce, &watch_nonce, &host_id)
        .unwrap();
    let peer_key = watch
        .derive_key(&host.public(), &host_nonce, &watch_nonce, &host_id)
        .unwrap();
    assert!(crypto::constant_time_eq(
        key.as_bytes(),
        peer_key.as_bytes()
    ));
    let host_private = SecretKey::from_slice(&host_scalar).unwrap();
    let watch_private = SecretKey::from_slice(&watch_scalar).unwrap();
    let z = p256::ecdh::diffie_hellman(
        host_private.to_nonzero_scalar(),
        watch_private.public_key().as_affine(),
    );
    let commit = crypto::commitment(&watch.public(), &watch_nonce);
    let commit_message = Message::PairCommit { commit }.encode().unwrap();
    let host_message = Message::PairHost {
        host_pub: host.public(),
        host_nonce,
        host_id,
        host_name: "omamori-pc".into(),
    }
    .encode()
    .unwrap();
    let reveal_message = Message::PairReveal {
        watch_pub: watch.public(),
        watch_nonce,
        watch_name: "Venu 4 ⌚".into(),
    }
    .encode()
    .unwrap();
    let th = crypto::transcript(&commit_message, &host_message, &reveal_message);
    let entry = Entry {
        req_id: [1, 2, 3, 4, 5, 6, 7, 8],
        kind: Kind::Sudo,
        needs_confirm: true,
        age_s: 42,
        title: "alice: sudo".into(),
        detail: "pacman -Syu --noconfirm on /dev/pts/1; UTF-8: 🦀".into(),
    };
    let mut pending = Message::Pending {
        host_id,
        host_name: "omamori-pc".into(),
        more: false,
        entries: vec![entry.clone()],
        mac: [0; 32],
    }
    .encode()
    .unwrap();
    let before_mac = pending[..pending.len() - 32].to_vec();
    let pending_mac = crypto::pending_mac(&key, &watch_nonce, &before_mac);
    let len = pending.len();
    pending[len - 32..].copy_from_slice(&pending_mac);
    let approve_mac = crypto::approve_mac(&key, &host_id, &watch_nonce, &entry);
    let approve = Message::Approve {
        req_id: entry.req_id,
        mac: approve_mac,
    }
    .encode()
    .unwrap();
    let result_mac = crypto::result_mac(&key, &watch_nonce, &entry.req_id, 0);
    let result = Message::Result {
        req_id: entry.req_id,
        status: 0,
        mac: result_mac,
    }
    .encode()
    .unwrap();
    let watch_confirm_mac = crypto::watch_confirm_mac(&key, &th, true);
    let host_confirm_mac = crypto::host_confirm_mac(&key, &th);
    json!({
        "version": 1,
        "byte_encoding": "hex (integers in wire messages are big-endian)",
        "pairing": {
            "host_private_scalar": hex(&host_scalar), "watch_private_scalar": hex(&watch_scalar),
            "host_public": hex(&host.public()), "watch_public": hex(&watch.public()),
            "host_nonce": hex(&host_nonce), "watch_nonce": hex(&watch_nonce), "host_id": hex(&host_id),
            "ecdh_z": hex(z.raw_secret_bytes()), "key": hex(key.as_bytes()),
            "commit": hex(&commit), "pair_commit_message": hex(&commit_message),
            "pair_host_message": hex(&host_message), "pair_reveal_message": hex(&reveal_message),
            "transcript_hash": hex(&th), "sas": crypto::sas(&key, &th),
            "watch_confirm_mac": hex(&watch_confirm_mac), "host_confirm_mac": hex(&host_confirm_mac),
            "pair_confirm_message": hex(&Message::PairConfirm { accepted: true, mac: watch_confirm_mac }.encode().unwrap()),
            "pair_result_message": hex(&Message::PairResult { accepted: true, mac: host_confirm_mac }.encode().unwrap())
        },
        "approval": {
            "req_id": hex(&entry.req_id), "kind": entry.kind as u8, "needs_confirm": entry.needs_confirm,
            "age_s": entry.age_s, "title": entry.title, "detail": entry.detail,
            "contents_hash": hex(&crypto::contents_hash(&entry)),
            "pending_before_mac": hex(&before_mac), "pending_mac": hex(&pending_mac), "pending_message": hex(&pending),
            "approve_mac": hex(&approve_mac), "approve_message": hex(&approve), "result_status": 0,
            "result_mac": hex(&result_mac), "result_message": hex(&result)
        },
        "framing": { "chunk_size": 20, "message": hex(&pending), "chunks": framing::chunk(&pending, 20).unwrap().iter().map(|c| hex(c)).collect::<Vec<_>>() }
    })
}
