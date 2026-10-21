mod common;
use common::{Rng, auth, entry};
use omamori_proto::{
    crypto::{self, Key},
    host, watch,
    wire::{Entry, Kind, Message},
};

fn assert_status(out: &omamori_proto::Output<host::Event>, expected: u8) {
    assert!(
        matches!(Message::decode(&out.messages[0]).unwrap(), Message::Result { status, .. } if status == expected)
    );
}

#[test]
fn lock_auto_sudo_requires_one_tap() {
    let (mut host, mut watch, auto, mut rng) = auth(vec![
        entry(1, Kind::Lock, false, 10),
        entry(2, Kind::Sudo, true, 20),
        entry(3, Kind::Sudo, true, 1),
    ]);
    assert_eq!(auto.messages.len(), 1);
    assert!(
        matches!(&auto.events[0], watch::Event::Show(entries) if entries.len() == 2 && entries.iter().all(|e| e.needs_confirm))
    );
    let approved = host.receive(&auto.messages[0], &mut rng).unwrap();
    assert!(matches!(
        approved.events.as_slice(),
        [host::Event::Approved([1, 1, 1, 1, 1, 1, 1, 1])]
    ));
    assert_status(&approved, 0);
    watch.receive(&approved.messages[0]).unwrap();
    for id in [2, 3] {
        let tap = watch.tap([id; 8]).unwrap();
        assert_eq!(tap.messages.len(), 1);
        let approved = host.receive(&tap.messages[0], &mut rng).unwrap();
        assert!(
            matches!(approved.events.as_slice(), [host::Event::Approved(req_id)] if *req_id == [id; 8])
        );
        let result = watch.receive(&approved.messages[0]).unwrap();
        assert!(matches!(
            result.events.as_slice(),
            [watch::Event::Result { status: 0, .. }]
        ));
        assert!(watch.tap([id; 8]).is_err());
    }
}

#[test]
fn auto_selects_oldest_unconfirmed_and_wire_order_on_ties() {
    for entries in [
        vec![
            entry(1, Kind::Lock, false, 2),
            entry(2, Kind::Sudo, false, 20),
            entry(3, Kind::Sudo, true, 90),
        ],
        vec![
            entry(2, Kind::Lock, false, 20),
            entry(1, Kind::Lock, false, 20),
        ],
    ] {
        let expected = if entries[0].req_id == [1; 8] {
            [2; 8]
        } else {
            [1; 8]
        };
        let (_, _, auto, _) = auth(entries);
        assert!(
            matches!(Message::decode(&auto.messages[0]).unwrap(), Message::Approve { req_id, .. } if req_id == expected)
        );
    }
}

#[test]
fn bad_pending_mac_or_wrong_host_rejected() {
    for wrong_host in [false, true] {
        let mut rng = Rng(17);
        let mut host = host::Session::authenticated([1; 16], "PC", Key::new([2; 32]));
        host.set_pending(vec![entry(1, Kind::Lock, false, 10)])
            .unwrap();
        let (mut watch, hello) = watch::Session::authenticated(
            if wrong_host { [3; 16] } else { [1; 16] },
            Key::new([2; 32]),
            &mut rng,
        );
        let mut pending = host
            .receive(&hello.messages[0], &mut rng)
            .unwrap()
            .messages
            .remove(0);
        if !wrong_host {
            let last = pending.len() - 1;
            pending[last] ^= 1;
        }
        assert!(watch.receive(&pending).is_err());
        assert!(watch.is_closed());
    }
}

#[test]
fn wrong_approve_mac_closes_session() {
    let (mut host, _, mut auto, mut rng) = auth(vec![entry(1, Kind::Lock, false, 10)]);
    auto.messages[0][10] ^= 1;
    let out = host.receive(&auto.messages[0], &mut rng).unwrap();
    assert!(out.events.is_empty());
    assert_status(&out, 2);
    assert!(host.is_closed());
    assert!(host.receive(&auto.messages[0], &mut rng).is_err());
}

#[test]
fn not_listed_expired_changed_and_double_approve_are_rejected() {
    let original = entry(1, Kind::Lock, false, 10);
    for change in 0..7 {
        let (mut host, _, auto, mut rng) = auth(vec![original.clone()]);
        match change {
            0 => host.set_pending(vec![]).unwrap(),
            1..=4 => {
                let mut updated = original.clone();
                match change {
                    1 => updated.title.push('!'),
                    2 => updated.detail.push('!'),
                    3 => updated.kind = Kind::Sudo,
                    4 => updated.needs_confirm = true,
                    _ => unreachable!(),
                }
                host.set_pending(vec![updated]).unwrap();
            }
            5 => {
                assert_eq!(
                    host.receive(&auto.messages[0], &mut rng)
                        .unwrap()
                        .events
                        .len(),
                    1
                );
            }
            6 => {
                // ID added to the queue after Pending: even a valid MAC is insufficient.
                let new = entry(2, Kind::Lock, false, 10);
                host.set_pending(vec![original.clone(), new.clone()])
                    .unwrap();
                let nonce = [9; 16];
                // Use a separate session to choose a known nonce without listing this ID.
                let mut other = host::Session::authenticated([1; 16], "PC", Key::new([2; 32]));
                other
                    .receive(
                        &Message::AuthHello { watch_nonce: nonce }.encode().unwrap(),
                        &mut rng,
                    )
                    .unwrap();
                other.set_pending(vec![new.clone()]).unwrap();
                let approve = Message::Approve {
                    req_id: new.req_id,
                    mac: crypto::approve_mac(&Key::new([2; 32]), &[1; 16], &nonce, &new),
                }
                .encode()
                .unwrap();
                let out = other.receive(&approve, &mut rng).unwrap();
                assert!(out.events.is_empty());
                assert_status(&out, 1);
                continue;
            }
            _ => unreachable!(),
        }
        let out = host.receive(&auto.messages[0], &mut rng).unwrap();
        assert!(out.events.is_empty());
        assert_status(&out, 1);
    }
}

#[test]
fn earlier_session_approve_replay_fails_with_different_nonce() {
    let request = entry(1, Kind::Lock, false, 1);
    let (_, _, old, _) = auth(vec![request.clone()]);
    let mut rng = Rng(999);
    let mut host = host::Session::authenticated([1; 16], "PC", Key::new([2; 32]));
    host.set_pending(vec![request]).unwrap();
    let (_, hello) = watch::Session::authenticated([1; 16], Key::new([2; 32]), &mut rng);
    host.receive(&hello.messages[0], &mut rng).unwrap();
    let out = host.receive(&old.messages[0], &mut rng).unwrap();
    assert!(out.events.is_empty());
    assert_status(&out, 2);
    assert!(host.is_closed());
}

#[test]
fn refresh_uses_new_nonce_and_never_reapproves() {
    let (mut host, mut watch, auto, mut rng) = auth(vec![
        entry(1, Kind::Lock, false, 1),
        entry(2, Kind::Lock, false, 2),
    ]);
    assert!(watch.refresh(&mut rng).is_err()); // wait for outstanding result
    let result = host.receive(&auto.messages[0], &mut rng).unwrap();
    watch.receive(&result.messages[0]).unwrap();
    let refresh = watch.refresh(&mut rng).unwrap();
    let pending = host.receive(&refresh.messages[0], &mut rng).unwrap();
    let next = watch.receive(&pending.messages[0]).unwrap();
    assert!(matches!(
        Message::decode(&next.messages[0]).unwrap(),
        Message::Approve {
            req_id: [1, 1, 1, 1, 1, 1, 1, 1],
            ..
        }
    ));
    let result = host.receive(&next.messages[0], &mut rng).unwrap();
    watch.receive(&result.messages[0]).unwrap();
    let refresh = watch.refresh(&mut rng).unwrap();
    let pending = host.receive(&refresh.messages[0], &mut rng).unwrap();
    assert!(
        watch
            .receive(&pending.messages[0])
            .unwrap()
            .messages
            .is_empty()
    );
}

#[test]
fn age_updates_do_not_invalidate_but_changed_then_restored_does() {
    let request = entry(1, Kind::Lock, false, 1);
    let (mut host, _, auto, mut rng) = auth(vec![request.clone()]);
    host.set_pending(vec![Entry {
        age_s: 2,
        ..request.clone()
    }])
    .unwrap();
    assert_eq!(
        host.receive(&auto.messages[0], &mut rng)
            .unwrap()
            .events
            .len(),
        1
    );

    let (mut host, _, auto, mut rng) = auth(vec![request.clone()]);
    host.set_pending(vec![Entry {
        title: "changed".into(),
        ..request.clone()
    }])
    .unwrap();
    host.set_pending(vec![request]).unwrap();
    let out = host.receive(&auto.messages[0], &mut rng).unwrap();
    assert!(out.events.is_empty());
    assert_status(&out, 1);
}

#[test]
fn duplicate_snapshot_ids_are_rejected_atomically() {
    let request = entry(1, Kind::Lock, false, 1);
    let (mut host, _, auto, mut rng) = auth(vec![request.clone()]);
    assert!(host.set_pending(vec![request.clone(), request]).is_err());
    assert_eq!(
        host.receive(&auto.messages[0], &mut rng)
            .unwrap()
            .events
            .len(),
        1
    );
}

#[test]
fn result_mac_verified_and_replay_rejected() {
    let (mut host, mut watch, auto, mut rng) = auth(vec![entry(1, Kind::Lock, false, 1)]);
    let mut result = host
        .receive(&auto.messages[0], &mut rng)
        .unwrap()
        .messages
        .remove(0);
    result[11] ^= 1;
    assert!(watch.receive(&result).is_err());
    assert!(watch.is_closed());

    let (mut host, mut watch, auto, mut rng) = auth(vec![entry(1, Kind::Lock, false, 1)]);
    let result = host
        .receive(&auto.messages[0], &mut rng)
        .unwrap()
        .messages
        .remove(0);
    watch.receive(&result).unwrap();
    assert!(watch.receive(&result).is_err());
    assert!(watch.is_closed());
}

#[test]
fn repeated_auth_nonce_is_rejected() {
    let mut rng = Rng(1);
    let mut host = host::Session::authenticated([1; 16], "PC", Key::new([2; 32]));
    let hello = Message::AuthHello {
        watch_nonce: [3; 16],
    }
    .encode()
    .unwrap();
    host.receive(&hello, &mut rng).unwrap();
    assert!(host.receive(&hello, &mut rng).is_err());
    assert!(host.is_closed());
}

#[test]
fn long_utf8_fields_match_watch_but_changes_beyond_wire_boundary_invalidate() {
    for field in ["title", "detail"] {
        let mut request = entry(1, Kind::Lock, false, 1);
        if field == "title" {
            request.title = "🦀".repeat(70);
        } else {
            request.detail = "🦀".repeat(70);
        }
        let (mut host, _, auto, mut rng) = auth(vec![request.clone()]);
        assert_eq!(
            host.receive(&auto.messages[0], &mut rng)
                .unwrap()
                .events
                .len(),
            1
        );

        let (mut host, _, auto, mut rng) = auth(vec![request.clone()]);
        if field == "title" {
            request.title.push('!');
        } else {
            request.detail.push('!');
        }
        host.set_pending(vec![request]).unwrap();
        let out = host.receive(&auto.messages[0], &mut rng).unwrap();
        assert!(out.events.is_empty());
        assert_status(&out, 1);
    }
}

#[test]
fn embedded_nul_contents_have_distinct_macs() {
    let mut a = entry(1, Kind::Sudo, true, 0);
    a.title = "a\0b".into();
    a.detail = "c".into();
    let mut b = a.clone();
    b.title = "a".into();
    b.detail = "b\0c".into();
    let mac = |e| crypto::approve_mac(&Key::new([2; 32]), &[1; 16], &[3; 16], e);
    assert_ne!(mac(&a), mac(&b));
}

#[test]
fn maximum_queue_is_paginated_oldest_first_and_refresh_drains_it() {
    let mut rng = Rng(781);
    let mut host = host::Session::authenticated([1; 16], &"h".repeat(255), Key::new([2; 32]));
    host.set_pending(
        (1..=16)
            .map(|id| Entry {
                title: "🦀".repeat(64),
                detail: "🦀".repeat(64),
                ..entry(id, Kind::Sudo, true, u16::from(id))
            })
            .collect(),
    )
    .unwrap();
    let (mut watch, mut hello) =
        watch::Session::authenticated([1; 16], Key::new([2; 32]), &mut rng);
    let mut seen = Vec::new();
    loop {
        let pending = host.receive(&hello.messages[0], &mut rng).unwrap();
        assert!(pending.messages[0].len() <= 1024);
        let Message::Pending { entries, more, .. } = Message::decode(&pending.messages[0]).unwrap()
        else {
            panic!()
        };
        if seen.is_empty() {
            assert!(more);
        }
        assert!(
            entries
                .iter()
                .all(|e| e.title.len() == 48 && e.detail.len() == 160)
        );
        watch.receive(&pending.messages[0]).unwrap();
        assert_eq!(watch.more(), more);
        for e in entries {
            seen.push(e.req_id[0]);
            let tap = watch.tap(e.req_id).unwrap();
            let result = host.receive(&tap.messages[0], &mut rng).unwrap();
            assert_status(&result, 0);
            watch.receive(&result.messages[0]).unwrap();
        }
        if !more {
            break;
        }
        hello = watch.refresh(&mut rng).unwrap();
    }
    assert_eq!(seen, (1..=16).rev().collect::<Vec<_>>());
}
