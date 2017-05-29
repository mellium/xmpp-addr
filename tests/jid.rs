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

use std::net::{Ipv6Addr, Ipv4Addr};

macro_rules! test_valid_addrs {
    ( $( $num:ident: [$jid:expr, $local:expr, $domain:expr, $res:expr] ),+ ) => {
        $(
            #[test]
            fn $num() {
                let v = vec![$jid, $local, $domain, $res];

                #[cfg(not(feature = "stable"))]
                let jid = Jid::try_from(v[0]).expect("Error parsing JID");
                #[cfg(feature = "stable")]
                let jid = Jid::from_str(v[0]).expect("Error parsing JID");

                match jid.local() {
                    None => assert_eq!(v[1], ""),
                    Some(l) =>  assert_eq!(v[1], l)
                }
                assert_eq!(v[2], jid.domain());
                match jid.resource() {
                    None => assert_eq!(v[3], ""),
                    Some(r) =>  assert_eq!(v[3], r)
                }
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

test_valid_addrs!(valid_00: ["example.net", "", "example.net", ""],
                 valid_01: ["example.net/rp", "", "example.net", "rp"],
                 valid_02: ["mERCUTIo@example.net", "mercutio", "example.net", ""],
                 valid_03: ["mercutio@example.net/rp", "mercutio", "example.net", "rp"],
                 valid_04: ["mercutio@example.net/rp@rp", "mercutio", "example.net", "rp@rp"],
                 valid_05: ["mercutio@example.net/rp@rp/rp", "mercutio", "example.net", "rp@rp/rp"],
                 valid_06: ["mercutio@example.net/@", "mercutio", "example.net", "@"],
                 valid_07: ["mercutio@example.net//@", "mercutio", "example.net", "/@"],
                 valid_08: ["mercutio@example.net//@//", "mercutio", "example.net", "/@//"],
                 valid_09: ["example.net.", "", "example.net", ""],
                 valid_10: ["test@example.net.", "test", "example.net", ""],
                 valid_11: ["test@example.net./rp", "test", "example.net", "rp"],
                 valid_12: ["example.net./rp", "", "example.net", "rp"],
                 valid_13: ["example.net.../rp", "", "example.net", "rp"],
                 valid_14: ["[::1]", "", "[::1]", ""],
                 valid_15: ["\u{212B}@example.net", "\u{00e5}", "example.net", ""]);

test_invalid_addrs!(invalid_00: "test@/test",
                   invalid_01: "lp@/rp",
                   invalid_02: r#"b"d@example.net"#,
                   invalid_03: r#"b&d@example.net"#,
                   invalid_04: r#"b'd@example.net"#,
                   invalid_05: r#"b:d@example.net"#,
                   invalid_06: r#"b<d@example.net"#,
                   invalid_07: r#"b>d@example.net"#,
                   invalid_08: r#"e@example.net/"#,
                   invalid_09: format!("{:width$}@example.net", "e", width=1024),
                   invalid_10: format!("example@{:width$}", "e", width=1024),
                   invalid_11: format!("e@example.net/{:width$}", "e", width=1024),
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
