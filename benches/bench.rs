#![feature(test)]
#![feature(try_from)]

extern crate test;
use test::Bencher;

extern crate xmpp_jid;
use xmpp_jid::Jid;

use std::convert::TryFrom;

#[bench]
fn parse_full(b: &mut Bencher) {
    b.iter(|| Jid::try_from("juliet@example.com/test"));
}

#[bench]
fn parse_bare(b: &mut Bencher) {
    b.iter(|| Jid::try_from("juliet@example.com"));
}

#[bench]
fn parse_domain(b: &mut Bencher) {
    b.iter(|| Jid::try_from("example.com"));
}

#[bench]
fn parse_ipv6_full(b: &mut Bencher) {
    b.iter(|| Jid::try_from("juliet@[::1]/test"));
}

#[bench]
fn parse_ipv6_bare(b: &mut Bencher) {
    b.iter(|| Jid::try_from("juliet@[::1]"));
}

#[bench]
fn parse_ipv6_domain(b: &mut Bencher) {
    b.iter(|| Jid::try_from("[::1]"));
}

#[bench]
fn string_full(b: &mut Bencher) {
    let j = Jid::try_from("juliet@example.com/test").unwrap();
    b.iter(|| format!("{}", j));
}

#[bench]
fn new_full(b: &mut Bencher) {
    b.iter(|| Jid::new("juliet", "example.com", "test"));
}
