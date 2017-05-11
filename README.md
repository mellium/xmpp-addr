# XMPP JID

[![Documentation](https://docs.rs/xmpp-jid/badge.svg)](https://docs.rs/xmpp-jid)
[![Crate](https://img.shields.io/crates/v/xmpp-jid.svg)](https://crates.io/crates/xmpp-jid)


An implementation of [RFC 7622], the XMPP Address Format, more commonly known as
"Jabber IDs" or "JIDs".

Currently, due to Rust not having a [PRECIS] implementation, this package is not
fully compliant with 7622. It only compiles on nightly Rust.

[RFC 7622]: https://tools.ietf.org/html/rfc7622
[PRECIS]: https://tools.ietf.org/html/rfc7564


## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
