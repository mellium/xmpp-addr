//! This crate is a place where I experiment with XMPP related topics in Rust.
//! It is not meant for release or to be used in production.
//!
//! Currently it contains a partial JID implementation, but nothing else.

#![deny(missing_docs)]
#![feature(try_from)]

#[macro_use]
extern crate serde_derive;
extern crate serde_xml_rs;

extern crate idna;

pub mod jid;
pub use jid::JID;
