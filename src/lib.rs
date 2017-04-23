#![feature(try_from)]

#[macro_use]
extern crate serde_derive;
extern crate serde_xml_rs;

extern crate idna;

pub mod jid;
pub use jid::JID;
