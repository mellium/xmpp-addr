// Copyright 2017 The Mellium Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(not(feature = "stable"), feature(try_from))]

extern crate xmpp_addr;
use xmpp_addr::{Jid, Error};


#[cfg(not(feature = "stable"))]
use std::convert::TryFrom;

use std::net::{Ipv6Addr, Ipv4Addr, IpAddr};

macro_rules! test_valid_split {
    ( $( $num:ident: [ $jid:expr, $local:expr, $domain:expr, $res:expr ] ),+ ) => {
        $(
            #[test]
            fn $num() {
                let j = $jid;
                let parts = Jid::split(j.as_ref());
                match parts {
                    Ok(p) => {
                        assert_eq!(p.0, $local);
                        assert_eq!(p.1, $domain);
                        assert_eq!(p.2, $res);
                    },
                    Err(e) => panic!(format!("Expected split to be valid, but got err: {:?}", e)),
                }
            }
        )*
    };
}

macro_rules! test_invalid_split {
    ( $( $num:ident: [ $jid:expr, $err:expr ] ),+ ) => {
        $(
            #[test]
            fn $num() {
                match Jid::split($jid) {
                    Err(_) => {
                        // TODO: Make sure this is the correct error.
                        // It's hard to test this right now because of:
                        // https://github.com/rust-lang/rust/issues/12832
                        let _ = $err;
                    },
                    _ => panic!("Errors did not match"),
                }
            }
        )*
    };
}

macro_rules! test_valid_addrs {
    ( $( $num:ident: [$jid:expr, $local:expr, $domain:expr, $res:expr] ),+ ) => {
        $(
            #[test]
            fn $num() {
                let j: &str = $jid;
                let lp: Option<&str> = $local;
                let dp = $domain;
                let rp: Option<&str> = $res;

                #[cfg(not(feature = "stable"))]
                let jid = Jid::try_from(j).expect("Error parsing JID");
                #[cfg(feature = "stable")]
                let jid = Jid::from_str(j).expect("Error parsing JID");

                assert_eq!(lp, jid.localpart());
                assert_eq!(dp, jid.domainpart());
                assert_eq!(rp, jid.resourcepart());
            }
        )*
    };
}

macro_rules! test_invalid_addrs {
    ( $( $num:ident: $jid:expr ),+ ) => {
        $(
            #[test]
            fn $num() {
                let j = $jid;
                #[cfg(not(feature = "stable"))]
                let jid = Jid::try_from(j.as_ref());
                #[cfg(feature = "stable")]
                let jid = Jid::from_str(j.as_ref());
                match jid {
                    Err(_) => {}
                    Ok(_) => {
                        panic!("Expected parsing JID to fail");
                    }
                }
            }
        )*
    };
}

test_valid_split!(valid_split_00: ["example.net", None, "example.net", None],
                  valid_split_01: ["example.net/rp", None, "example.net", Some("rp")],
                  valid_split_02: ["lp@example.net", Some("lp"), "example.net", None],
                  valid_split_03: ["lp@example.net/rp", Some("lp"), "example.net", Some("rp")],
                  valid_split_04: ["lp@example.net./rp", Some("lp"), "example.net", Some("rp")],
                  valid_split_05: ["lp@example.net.../rp", Some("lp"), "example.net", Some("rp")],
                  // TODO: Figure out how to take an Option<String> so that format can be used.
                  valid_split_06: ["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee@example.net", Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), "example.net", None],
                  valid_split_07: ["example.net/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", None, "example.net", Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")]);

test_invalid_split!(invalid_split_00: ["",             Error::EmptyJid],
                    invalid_split_01: ["@example.net", Error::EmptyLocal],
                    invalid_split_02: ["example.net/", Error::EmptyResource],
                    invalid_split_04: ["lp@/rp",       Error::ShortDomain]);

test_valid_addrs!(valid_00: ["example.net", None, "example.net", None],
                 valid_01: ["example.net/rp", None, "example.net", Some("rp")],
                 valid_02: ["mERCUTIo@example.net", Some("mercutio"), "example.net", None],
                 valid_03: ["mercutio@example.net/rp", Some("mercutio"), "example.net", Some("rp")],
                 valid_04: ["mercutio@example.net/rp@rp", Some("mercutio"), "example.net", Some("rp@rp")],
                 valid_05: ["mercutio@example.net/rp@rp/rp", Some("mercutio"), "example.net", Some("rp@rp/rp")],
                 valid_06: ["mercutio@example.net/@", Some("mercutio"), "example.net", Some("@")],
                 valid_07: ["mercutio@example.net//@", Some("mercutio"), "example.net", Some("/@")],
                 valid_08: ["mercutio@example.net//@//", Some("mercutio"), "example.net", Some("/@//")],
                 valid_09: ["example.net.", None, "example.net", None],
                 valid_10: ["test@example.net.", Some("test"), "example.net", None],
                 valid_11: ["test@example.net./rp", Some("test"), "example.net", Some("rp")],
                 valid_12: ["example.net./rp", None, "example.net", Some("rp")],
                 valid_13: ["example.net.../rp", None, "example.net", Some("rp")],
                 valid_14: ["[::1]", None, "[::1]", None],
                 valid_15: ["\u{212B}@example.net", Some("\u{00e5}"), "example.net", None]);

test_invalid_addrs!(invalid_00: "@example.net/test",
                   invalid_01: "lp@/rp",
                   invalid_02: r#"b"d@example.net"#,
                   invalid_03: r#"b&d@example.net"#,
                   invalid_04: r#"b'd@example.net"#,
                   invalid_05: r#"b:d@example.net"#,
                   invalid_06: r#"b<d@example.net"#,
                   invalid_07: r#"b>d@example.net"#,
                   invalid_08: r#"e@example.net/"#,
                   invalid_09: format!("{:e^width$}@example.net", "e", width=1024),
                   invalid_10: format!("example@{:e^width$}", "e", width=1024),
                   invalid_11: format!("e@example.net/{:e^width$}", "e", width=1024),
                   invalid_12: r#""#,
                   invalid_13: r#"[]"#,
                   invalid_14: r#"[1.1.1.1]"#,
                   invalid_15: r#"lp@"#,
                   invalid_16: r#"lp@/"#,
                   invalid_17: r#"@/rp"#,
                   invalid_18: r#"/rp"#,
                   invalid_19: r#"@/"#,
                   invalid_20: r#"/"#,
                   invalid_21: r#"@"#,
                   invalid_22: r#"["#);

#[test]
fn test_display() {
    let jid = Jid::from_str("domain/res").unwrap();
    assert_eq!(jid.to_string(), "domain/res");

    let jid = Jid::from_str("local@domain/res").unwrap();
    assert_eq!(jid.to_string(), "local@domain/res");

    let jid = Jid::from_str("local@domain").unwrap();
    assert_eq!(jid.to_string(), "local@domain");

    let jid = Jid::from_str("domain").unwrap();
    assert_eq!(jid.to_string(), "domain");

    let jid = Jid::from_str("[::1]").unwrap();
    assert_eq!(jid.to_string(), "[::1]");

    let v6: Ipv6Addr = "::1".parse().unwrap();
    let jid: Jid = v6.into();
    assert_eq!(jid.to_string(), "[::1]");

    let v4: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let jid: Jid = v4.into();
    assert_eq!(jid.to_string(), "127.0.0.1");

    let addr: IpAddr = IpAddr::V4(v4);
    let jid: Jid = addr.into();
    assert_eq!(jid.to_string(), "127.0.0.1");

    let addr: IpAddr = IpAddr::V6(v6);
    let jid: Jid = addr.into();
    assert_eq!(jid.to_string(), "[::1]");
}

#[test]
fn test_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Jid>();
    assert_send::<Error>();
    assert_send::<xmpp_addr::Result<Jid>>();
}

#[test]
fn test_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<Jid>();
    assert_sync::<Error>();
    assert_sync::<xmpp_addr::Result<Jid>>();
}
