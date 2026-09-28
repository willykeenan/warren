use std::{mem::size_of, ptr};
use warren_ffi::*;
fn bytes(s: &str) -> Bytes {
    Bytes {
        ptr: s.as_ptr(),
        len: s.len() as u32,
    }
}
fn result() -> ResultV1 {
    ResultV1 {
        struct_size: size_of::<ResultV1>() as u32,
        flags: 99,
        count: 99,
        reserved: 99,
        value: 99,
    }
}
#[test]
fn invalid_state_handles_and_cancel_before_dispatch() {
    unsafe {
        assert_eq!(wr_v1_abi_version(), 1);
        let home = "/ffi-validation-only/no-files-created";
        let mut cfg = Config {
            struct_size: size_of::<Config>() as u32,
            abi_version: 1,
            storage_root: bytes(home),
            reserved: [0; 4],
        };
        let mut h = 99;
        cfg.reserved[0] = 1;
        assert_eq!(wr_v1_context_create(&cfg, &mut h), -1);
        assert_eq!(h, 0);
        cfg.reserved[0] = 0;
        assert_eq!(wr_v1_context_create(&cfg, &mut h), 0);
        assert_ne!(h, 0);
        let mut other = 99;
        assert_eq!(wr_v1_context_create(&cfg, &mut other), -5);
        assert_eq!(other, 0);
        let mut state = 99;
        let mut connected = 99;
        assert_eq!(wr_v1_context_state(h, &mut state, &mut connected), 0);
        assert_eq!((state, connected), (0, 0));
        let mut op = 0;
        assert_eq!(wr_v1_operation_create(h, &mut op), 0);
        assert_eq!(wr_v1_operation_release(op), -4);
        assert_eq!(wr_v1_context_destroy(h), -4);
        assert_eq!(wr_v1_operation_cancel(op), 0);
        let mut out = result();
        assert_eq!(wr_v1_start(h, op, 1, &mut out), -6);
        assert_eq!(
            (out.flags, out.count, out.value, out.reserved),
            (0, 0, 0, 0)
        );
        assert_eq!(wr_v1_operation_release(op), 0);
        assert_eq!(wr_v1_operation_cancel(op), -2);
        let mut replacement = 0;
        assert_eq!(wr_v1_operation_create(h, &mut replacement), 0);
        assert_ne!(replacement, op);
        out = result();
        assert_eq!(
            wr_v1_open_private_pinned(
                h,
                replacement,
                bytes("peer"),
                0,
                [7u8; 32].as_ptr(),
                1,
                &mut out
            ),
            -1
        );
        assert_eq!((out.flags, out.count, out.value), (0, 0, 0));
        assert_eq!(wr_v1_operation_cancel(replacement), 0);
        assert_eq!(wr_v1_operation_release(replacement), 0);
        out = result();
        assert_eq!(wr_v1_read(0, 0, ptr::null_mut(), 1, 1, &mut out), -1);
        assert_eq!((out.flags, out.count, out.value), (0, 0, 0));
        let mut many = Vec::new();
        for _ in 0..64 {
            let mut o = 0;
            assert_eq!(wr_v1_operation_create(h, &mut o), 0);
            many.push(o);
        }
        let mut overflow = 99;
        assert_eq!(wr_v1_operation_create(h, &mut overflow), -5);
        assert_eq!(overflow, 0);
        for o in many {
            assert_eq!(wr_v1_operation_cancel(o), 0);
            assert_eq!(wr_v1_operation_release(o), 0);
        }
        let mut unclaimed = 0;
        assert_eq!(wr_v1_operation_create(h, &mut unclaimed), 0);
        assert_eq!(wr_v1_stop(h, 5000), 0);
        assert_eq!(wr_v1_operation_release(unclaimed), 0);
        assert_eq!(wr_v1_context_destroy(h), 0);
        assert_eq!(wr_v1_context_destroy(h), -2);
        assert!(!std::path::Path::new(home).exists());
    }
}
