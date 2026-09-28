#[path = "../../../tests/common/mod.rs"]
mod common;
use crate::*;
use std::{mem::size_of, time::Duration};
fn bytes(s: &str) -> Bytes {
    Bytes {
        ptr: s.as_ptr(),
        len: s.len() as u32,
    }
}
fn result() -> ResultV1 {
    ResultV1 {
        struct_size: size_of::<ResultV1>() as u32,
        ..Default::default()
    }
}
unsafe fn op(h: u64) -> u64 {
    let mut o = 0;
    assert_eq!(wr_v1_operation_create(h, &mut o), 0);
    o
}
unsafe fn call(h: u64, f: impl FnOnce(u64, &mut ResultV1) -> i32) -> (i32, ResultV1) {
    let o = op(h);
    let mut r = result();
    let status = f(o, &mut r);
    assert_eq!(wr_v1_operation_release(o), 0);
    (status, r)
}
#[test]
fn real_relay_noise_halfclose_remainder_concurrent_cancel_and_no_late_pointer_use() {
    unsafe {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut relay = rt.block_on(common::start_relay());
        let mut server = rt.block_on(common::enroll_started(&relay, "server"));
        let (port, _) = rt.block_on(common::echo_server());
        server.share(port, None);
        let key = server.identity().static_pub;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("client");
        let home = home.to_str().unwrap();
        let cfg = Config {
            struct_size: size_of::<Config>() as u32,
            abi_version: 1,
            storage_root: bytes(home),
            reserved: [0; 4],
        };
        let mut h = 0;
        assert_eq!(wr_v1_context_create(&cfg, &mut h), 0);
        let invite = relay.invite(Some("client"));
        let url = relay.url();
        let join = Join {
            struct_size: size_of::<Join>() as u32,
            has_relay_certificate_pin: 1,
            relay_https: bytes(&url),
            invite: bytes(&invite),
            node_name: bytes("client"),
            relay_certificate_sha256: relay.pin,
        };
        assert_eq!(call(h, |o, r| wr_v1_join(h, o, &join, 10000, r)).0, 0);
        assert_eq!(call(h, |o, r| wr_v1_start(h, o, 10000, r)).0, 0);
        // Explicit approval is mandatory even when the caller already knows the key.
        let (denied, denied_result) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 5000, r)
        });
        assert_eq!(denied, PIN_REJECTED);
        assert_eq!(denied_result.value, 0);
        assert_eq!(
            call(h, |o, r| wr_v1_pin_approve(
                h,
                o,
                bytes("server"),
                key.as_ptr(),
                5000,
                r
            ))
            .0,
            0
        );
        let wrong_key = [0x42u8; 32];
        assert_ne!(wrong_key, key);
        assert_eq!(
            call(h, |o, r| wr_v1_pin_approve(
                h,
                o,
                bytes("server"),
                wrong_key.as_ptr(),
                5000,
                r
            ))
            .0,
            PIN_REJECTED
        );
        assert_eq!(
            call(h, |o, r| wr_v1_open_private_pinned(
                h,
                o,
                bytes("server"),
                port,
                wrong_key.as_ptr(),
                5000,
                r
            ))
            .0,
            PIN_REJECTED
        );
        let (status, r) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 10000, r)
        });
        assert_eq!(status, 0);
        let stream = r.value;
        // One reader blocks while a writer sends on the opposite direction.
        let read_op = op(h);
        let reader = std::thread::spawn(move || {
            let mut b = [0xa5u8; 3];
            let mut r = result();
            let s = wr_v1_read(stream, read_op, b.as_mut_ptr(), 3, 10000, &mut r);
            (s, r, b)
        });
        let payload = vec![42u8; 50000];
        let (s, w) = call(h, |o, r| {
            wr_v1_write(stream, o, payload.as_ptr(), payload.len() as u32, 5000, r)
        });
        assert_eq!((s, w.count), (0, payload.len() as u32));
        let (s, r, b) = reader.join().unwrap();
        assert_eq!(s, 0);
        assert_eq!(r.count, 3);
        assert_eq!(b, [42; 3]);
        assert_eq!(wr_v1_operation_release(read_op), 0);
        assert_eq!(call(h, |o, r| wr_v1_finish_write(stream, o, 5000, r)).0, 0);
        assert_eq!(call(h, |o, r| wr_v1_finish_write(stream, o, 5000, r)).0, -3);
        let mut got = 3;
        loop {
            let mut b = [0u8; 997];
            let (s, r) = call(h, |o, r| {
                wr_v1_read(stream, o, b.as_mut_ptr(), 997, 5000, r)
            });
            if s == 1 {
                assert_eq!(r.count, 0);
                break;
            }
            assert_eq!(s, 0);
            assert!(r.count > 0);
            assert!(b[..r.count as usize].iter().all(|v| *v == 42));
            got += r.count as usize;
        }
        assert_eq!(got, payload.len());
        let mut b = [0u8; 1];
        assert_eq!(
            call(h, |o, r| wr_v1_read(stream, o, b.as_mut_ptr(), 1, 5000, r)).0,
            1
        );
        assert_eq!(wr_v1_stream_close(stream, 5000), 0);
        // Terminal choice is not the end of the C call: output is still borrowed.
        let (status, r) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 10000, r)
        });
        assert_eq!(status, 0);
        let stream = r.value;
        let marker = b"held-output";
        assert_eq!(
            call(h, |o, r| wr_v1_write(
                stream,
                o,
                marker.as_ptr(),
                marker.len() as u32,
                5000,
                r
            ))
            .0,
            0
        );
        let pause = tests_hooks::Pause::new();
        *handles::lock(&tests_hooks::READ_TERMINAL) = Some((stream, pause.clone()));
        let read_op = op(h);
        let reader = std::thread::spawn(move || {
            let mut b = [0xa5u8; 11];
            let mut r = result();
            let status = wr_v1_read(stream, read_op, b.as_mut_ptr(), 11, 5000, &mut r);
            (status, r, b)
        });
        pause.reached.wait();
        *handles::lock(&tests_hooks::READ_TERMINAL) = None;
        assert_eq!(
            wr_v1_operation_release(read_op),
            -4,
            "terminal call still owns its output"
        );
        assert_eq!(
            wr_v1_stream_close(stream, 1),
            -7,
            "close must await caller-buffer epilogue"
        );
        pause.resume.wait();
        let (status, r, b) = reader.join().unwrap();
        assert_eq!(status, 0);
        assert_eq!(r.count, 11);
        assert_eq!(&b, marker);
        assert_eq!(wr_v1_operation_release(read_op), 0);
        assert_eq!(wr_v1_stream_close(stream, 5000), 0);
        // Cancel a pending read, then mutate its formerly borrowed buffer after return.
        let (s, r) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 10000, r)
        });
        assert_eq!(s, 0);
        let stream = r.value;
        let read_op = op(h);
        let admission = tests_hooks::Pause::new();
        *handles::lock(&tests_hooks::READ_ADMITTED) = Some((stream, admission.clone()));
        let reader = std::thread::spawn(move || {
            let mut b = Box::new([0xa5u8; 64]);
            let mut r = result();
            let status = wr_v1_read(stream, read_op, b.as_mut_ptr(), 64, 10000, &mut r);
            (status, r, b)
        });
        admission.reached.wait();
        *handles::lock(&tests_hooks::READ_ADMITTED) = None;
        let mut probe = [0u8; 1];
        assert_eq!(
            call(h, |o, r| wr_v1_read(
                stream,
                o,
                probe.as_mut_ptr(),
                1,
                1000,
                r
            ))
            .0,
            -4
        );
        assert_eq!(wr_v1_operation_cancel(read_op), 0);
        admission.resume.wait();
        let (status, r, mut b) = reader.join().unwrap();
        assert_eq!(status, -6);
        assert_eq!(r.count, 0);
        assert_eq!(*b, [0xa5; 64]);
        assert_eq!(wr_v1_operation_release(read_op), 0);
        b.fill(0x5a);
        assert_eq!(wr_v1_stream_close(stream, 5000), 0);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(*b, [0x5a; 64]);
        let (status, r) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 10000, r)
        });
        assert_eq!(status, 0);
        let stream = r.value;
        let read_op = op(h);
        let admission = tests_hooks::Pause::new();
        *handles::lock(&tests_hooks::READ_ADMITTED) = Some((stream, admission.clone()));
        let reader = std::thread::spawn(move || {
            let mut b = [0x33; 16];
            let mut r = result();
            wr_v1_read(stream, read_op, b.as_mut_ptr(), 16, 10000, &mut r)
        });
        admission.reached.wait();
        *handles::lock(&tests_hooks::READ_ADMITTED) = None;
        admission.resume.wait();
        // Exact-key forget drains active bridge traffic before removing approval.
        assert_eq!(
            call(h, |o, r| wr_v1_pin_forget(
                h,
                o,
                bytes("server"),
                key.as_ptr(),
                10000,
                r
            ))
            .0,
            OK
        );
        assert_eq!(reader.join().unwrap(), CANCELLED);
        assert_eq!(wr_v1_operation_release(read_op), OK);
        assert_eq!(wr_v1_stream_close(stream, 1), INVALID_HANDLE);
        assert_eq!(
            call(h, |o, r| wr_v1_open_private_pinned(
                h,
                o,
                bytes("server"),
                port,
                key.as_ptr(),
                5000,
                r
            ))
            .0,
            PIN_REJECTED
        );
        assert_eq!(
            call(h, |o, r| wr_v1_pin_approve(
                h,
                o,
                bytes("server"),
                key.as_ptr(),
                5000,
                r
            ))
            .0,
            OK
        );
        let (status, r) = call(h, |o, r| {
            wr_v1_open_private_pinned(h, o, bytes("server"), port, key.as_ptr(), 10000, r)
        });
        assert_eq!(status, OK);
        let stream = r.value;
        let read_op = op(h);
        let admission = tests_hooks::Pause::new();
        *handles::lock(&tests_hooks::READ_ADMITTED) = Some((stream, admission.clone()));
        let reader = std::thread::spawn(move || {
            let mut b = [0x33; 16];
            let mut r = result();
            wr_v1_read(stream, read_op, b.as_mut_ptr(), 16, 10000, &mut r)
        });
        admission.reached.wait();
        *handles::lock(&tests_hooks::READ_ADMITTED) = None;
        admission.resume.wait();
        assert_eq!(wr_v1_stop(h, 10000), OK);
        assert_eq!(reader.join().unwrap(), CANCELLED);
        assert_eq!(wr_v1_operation_release(read_op), OK);
        assert_eq!(wr_v1_stream_close(stream, 1), INVALID_HANDLE);
        assert_eq!(wr_v1_context_destroy(h), OK);
        rt.block_on(server.stop());
        rt.block_on(relay.stop());
    }
}
