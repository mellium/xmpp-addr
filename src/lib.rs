// Copyright 2017 The Mellium Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implements the XMPP Address Format as defined in RFC 7622.
//!
//! For historical reasons, XMPP addresses are called "Jabber Identifiers", or JIDs. JIDs are
//! comprised of three parts: the localpart (a username or account), the domainpart (the server),
//! and the resourcepart (a specific client) and look more or less like an email where the first
//! two parts are demarcated by the '@' character but with the
//! resourcepart added to the end and demarcated by the '/' character, eg:
//!
//! > localpart@domainpart/resourcepart
//!
//! Like email, JIDs allow routing across networks based on the domainpart, and local routing based
//! on the localpart. Unlike emails however, JIDs also allow for last-mile-delivery to *specific*
//! clients (or "resources") using the resourcepart. Also unlike email, JIDs support
//! internationalization.
//!
//! **Note well** that this package currently isn't fully compliant with [RFC 7622]; it does not
//! perform the PRECIS ([RFC 7564]) enforcement step.
//!
//! [RFC 7622]: https://tools.ietf.org/html/rfc7622
//! [RFC 7564]: https://tools.ietf.org/html/rfc7564
//!
//! # Features
//!
//! The following feature flag can be used when compiling the crate:
//!
//! - `stable` — only build with stable APIs (no `TryFrom` impls)
//!
//! It is on by default. To use unstable features on a nightly version of rust, build and test
//! with the `--no-default-features` flag.
//!
//! # Examples
//!
//! ## From parts (stable)
//!
//! ```rust
//! # use xmpp_addr::Jid;
//! # fn try_main() -> Result<(), xmpp_addr::Error> {
//! let j = Jid::new("feste", "example.net", None)?;
//! assert_eq!(j, "feste@example.net");
//! #     Ok(())
//! # }
//! # fn main() {
//! #   try_main().unwrap();
//! # }
//! ```
//!
//! ## From parts (nightly)
//!
#![cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#![cfg_attr(not(feature = "stable"), doc = " ```rust")]
//! #![feature(try_from)]
//! # use std::convert::{ TryInto, TryFrom };
//! # use xmpp_addr::Jid;
//! # fn try_main() -> Result<(), xmpp_addr::Error> {
//! let j: Jid = ("feste", "example.net").try_into()?;
//! assert_eq!(j, "feste@example.net");
//!
//! let j = Jid::try_from(("feste", "example.net", "avsgasje"))?;
//! assert_eq!(j, "feste@example.net/avsgasje");
//! #     Ok(())
//! # }
//! # fn main() {
//! #   try_main().unwrap();
//! # }
//! ```
//!
//! ## Parsing (stable)
//!
//! ```rust
//! # use xmpp_addr::Jid;
//! # fn try_main() -> Result<(), xmpp_addr::Error> {
//! let j = Jid::from_str("juliet@example.net/balcony")?;
//! assert_eq!(j.localpart(), Some("juliet"));
//! assert_eq!(j.domainpart(), "example.net");
//! assert_eq!(j.resourcepart(), Some("balcony"));
//! #     Ok(())
//! # }
//! # fn main() {
//! #   try_main().unwrap();
//! # }
//! ```
//!
//! ## Parsing (nightly)
//!
#![cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#![cfg_attr(not(feature = "stable"), doc = " ```rust")]
//! #![feature(try_from)]
//! # use std::convert::{ TryInto, TryFrom };
//! # use xmpp_addr::Jid;
//! # fn try_main() -> Result<(), xmpp_addr::Error> {
//! let j: Jid = "orsino@example.net/ilyria".try_into()?;
//! assert_eq!(j, "orsino@example.net/ilyria");
//!
//! let j = Jid::try_from("juliet@example.net/balcony")?;
//! assert_eq!(j, "juliet@example.net/balcony");
//! #     Ok(())
//! # }
//! # fn main() {
//! #   try_main().unwrap();
//! # }
//! ```

#![deny(missing_docs)]
#![cfg_attr(not(feature = "stable"), feature(try_from))]
#![cfg_attr(not(feature = "stable"), feature(ascii_ctype))]

#![doc(html_root_url = "https://docs.rs/xmpp-addr/0.11.1")]

extern crate idna;
extern crate unicode_normalization;

use unicode_normalization::UnicodeNormalization;

use std::convert;

use std::ascii::AsciiExt;
use std::borrow;
use std::cmp;
use std::fmt;
use std::net;
use std::result;
use std::str;
use std::str::FromStr;

/// Possible error values that can occur when parsing JIDs.
#[derive(Debug)]
pub enum Error {
    /// Returned if an empty string is being parsed.
    EmptyJid,

    /// Returned if the localpart is empty (eg. "@example.net").
    EmptyLocal,

    /// Returned if the localpart is longer than 1023 bytes.
    LongLocal,

    /// Returned if the domain part is too short to be a valid domain, hostname, or IP address.
    ShortDomain,

    /// Returned if the domain part is too long to be a valid domain.
    LongDomain,

    /// Returned if the resourcepart is empty (eg. "example.net/"
    EmptyResource,

    /// Returned if the resourcepart is longer than 1023 bytes.
    LongResource,

    /// Returned if a forbidden character was found in any part of the JID.
    ForbiddenChars,

    /// Returned if an error occured while attempting to parse the domainpart of the JID as an IPv6
    /// address.
    Addr(net::AddrParseError),

    /// Returned if an error occured while performing IDNA2008 processing on the domainpart of the
    /// JID.
    IDNA(idna::uts46::Errors),
}

/// A custom result type for JIDs that elides the [error type].
///
/// [error type]: ./enum.Error.html
pub type Result<T> = result::Result<T, Error>;

/// A parsed JID.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Jid<'a> {
    local: Option<borrow::Cow<'a, str>>,
    domain: borrow::Cow<'a, str>,
    resource: Option<borrow::Cow<'a, str>>,
}

impl<'a> Jid<'a> {
    /// Splits a JID formatted as a string into its localpart, domainpart, and resourcepart.
    /// The localpart and resourcepart are optional, but the domainpart is always returned.
    ///
    /// # Errors
    ///
    /// This function performs a "naive" string split and does not perform any validation of the
    /// individual parts other than to make sure that required parts exist. For example
    /// "@example.com" will return an error ([`EmptyLocal`]), but "%@example.com" will not (even
    /// though "%" is not a valid localpart). The length of localparts and resourceparts is also
    /// not checked (other than if they're empty). This is because when creating an actual JID it
    /// is possible for certain Unicode characters to be canonicalized into a shorter length
    /// encoding, meaning that a part that was previously too long may suddenly fit in the maximum
    /// length. [`ShortDomain`] may be returned because we know that domains will never become
    /// longer after performing IDNA2008 operations, but [`LongDomain`] may not be returned for the
    /// same reasons as mentioned above.
    ///
    /// Possible errors include:
    ///
    ///   - [`EmptyJid`]  \(eg. `""`)
    ///   - [`EmptyLocal`]  \(`"@example.com"`)
    ///   - [`EmptyResource`]  \(`"example.com/"`)
    ///   - [`ShortDomain`]  \(`"a"`, `"foo@/bar"`)
    ///
    /// [error variant]: ./enum.Error.html
    /// [`EmptyJid`]: ./enum.Error.html#EmptyJid.v
    /// [`EmptyLocal`]: ./enum.Error.html#EmptyLocal.v
    /// [`EmptyResource`]: ./enum.Error.html#EmptyResource.v
    /// [`ShortDomain`]: ./enum.Error.html#ShortDomain.v
    /// [`LongDomain`]: ./enum.Error.html#LongDomain.v
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let (lp, dp, rp) = Jid::split("feste@example.net")?;
    /// assert_eq!(lp, Some("feste"));
    /// assert_eq!(dp, "example.net");
    /// assert_eq!(rp, None);
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn split(s: &'a str) -> Result<(Option<&'a str>, &'a str, Option<&'a str>)> {
        if s == "" {
            return Err(Error::EmptyJid);
        }

        // RFC 7622 §3.1.  Fundamentals:
        //
        //    Implementation Note: When dividing a JID into its component parts,
        //    an implementation needs to match the separator characters '@' and
        //    '/' before applying any transformation algorithms, which might
        //    decompose certain Unicode code points to the separator characters.
        //
        // so let's do that now. First we'll parse the domainpart using the rules
        // defined in §3.2:
        //
        //    The domainpart of a JID is the portion that remains once the
        //    following parsing steps are taken:
        //
        //    1.  Remove any portion from the first '/' character to the end of the
        //        string (if there is a '/' character present).

        let mut chars = s.char_indices();
        let sep = chars.find(|&c| match c {
            (_, '@') | (_, '/') => true,
            _ => false,
        });

        let (lpart, dpart, rpart) = match sep {
            // If there are no part separators at all, the entire string is a domainpart.
            None => (None, s, None),
            // There is a resource part, and we did not find a localpart (the first separator found
            // was the first '/').
            Some((i, '/')) => (None, &s[0..i], Some(&s[i + 1..])),
            // The JID ends with the '@' sign
            Some((i, '@')) if i + 1 == s.len() => return Err(Error::ShortDomain),
            // We found a local part, so keep searching to try and find a resource part.
            Some((i, '@')) => {
                // Continue looking for a '/'.
                let slash = chars.find(|&c| match c {
                    (_, '/') => true,
                    _ => false,
                });

                // RFC 7622 §3.3.1 provides a small table of characters which are still not allowed in
                // localpart's even though the IdentifierClass base class and the UsernameCaseMapped
                // profile don't forbid them; disallow them here.
                if s[0..i].contains(&['"', '&', '\'', '/', ':', '<', '>', '@', '`'][..]) {
                    return Err(Error::ForbiddenChars);
                }
                match slash {
                    // This is a bare JID.
                    None => (Some(&s[0..i]), &s[i + 1..], None),
                    // There is a '/', but it's immediately after the '@' (or there is a short
                    // domain part between them).
                    Some((j, _)) if j - i < 3 => return Err(Error::ShortDomain),
                    // This is a full JID.
                    Some((j, _)) => (Some(&s[0..i]), &s[i + 1..j], Some(&s[j + 1..])),
                }
            }
            _ => unreachable!(),
        };

        // We'll throw out any trailing dots on domainparts, since they're ignored:
        //
        //    If the domainpart includes a final character considered to be a label
        //    separator (dot) by [RFC1034], this character MUST be stripped from
        //    the domainpart before the JID of which it is a part is used for the
        //    purpose of routing an XML stanza, comparing against another JID, or
        //    constructing an XMPP URI or IRI [RFC5122].  In particular, such a
        //    character MUST be stripped before any other canonicalization steps
        //    are taken.
        Ok((lpart, dpart.trim_right_matches('.'), rpart))
    }

    /// Constructs a JID from its constituent parts. The localpart is generally the username of a
    /// user on a particular server, the domainpart is a domain, hostname, or IP address where the
    /// user or entity resides, and the resourcepart identifies a specific client. Everything but
    /// the domain is optional.
    ///
    /// # Errors
    ///
    /// If the localpart or resourcepart passed to this function is not valid, or the domainpart
    /// fails IDNA processing or is not a valid IPv6 address, this function returns an [error
    /// variant].
    ///
    /// [error variant]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::new("feste", "example.net", None)?;
    /// assert_eq!(j, "feste@example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn new<L, R>(local: L, domain: &'a str, resource: R) -> Result<Jid<'a>>
    where
        L: Into<Option<&'a str>>,
        R: Into<Option<&'a str>>,
    {
        Ok(Jid {
            local: match local.into() {
                None => None,
                Some(l) => Some(Jid::process_local(l)?),
            },
            domain: match Jid::process_domain(domain) {
                Err(err) => return Err(err),
                Ok(d) => d,
            },
            resource: match resource.into() {
                None => None,
                Some(r) => Some(Jid::process_resource(r)?),
            },
        })
    }

    fn process_local(local: &'a str) -> Result<borrow::Cow<'a, str>> {
        // TODO: This should all be handled by the PRECIS UsernameCaseMapped profile.
        let local: borrow::Cow<'a, str> = if local.is_ascii() {
            // ASCII fast path
            // TODO: JIDs aren't likely to have long localparts; are multiple scans worth it just
            // to maybe avoid an allocation? Probably not.
            #[cfg(not(feature = "stable"))]
            let is_lower = local.is_ascii_lowercase();
            #[cfg(feature = "stable")]
            let is_lower = local.bytes().find(|&c| b'A' <= c && c <= b'Z').is_none();

            if is_lower {
                local.into()
            } else {
                local.to_ascii_lowercase().into()
            }
        } else {
            // Contains characters outside the ASCII range (needs NFC)
            local.chars().flat_map(|c| c.to_lowercase()).nfc().collect()
        };
        match local.len() {
            0 => Err(Error::EmptyLocal),
            l if l > 1023 => Err(Error::LongLocal),
            _ => Ok(local),
        }
    }

    fn process_domain(domain: &'a str) -> Result<borrow::Cow<'a, str>> {
        let is_v6 = if domain.starts_with('[') && domain.ends_with(']') {
            // This should be an IPv6 address, validate it.
            let inner = unsafe { domain.slice_unchecked(1, domain.len() - 1) };
            match net::Ipv6Addr::from_str(inner) {
                Ok(_) => true,
                Err(v) => return Err(Error::Addr(v)),
            }
        } else {
            false
        };

        let dlabel: borrow::Cow<'a, str> = if !is_v6 {
            let (dlabel, result) = idna::domain_to_unicode(domain);
            match result {
                Ok(_) => dlabel.into(),
                Err(e) => return Err(Error::IDNA(e)),
            }
        } else {
            domain.into()
        };

        if dlabel.len() > 1023 {
            return Err(Error::LongDomain);
        }
        if dlabel.len() < 1 {
            return Err(Error::ShortDomain);
        }

        Ok(dlabel)
    }

    fn process_resource(res: &'a str) -> Result<borrow::Cow<'a, str>> {
        let res: borrow::Cow<'a, str> = if res.is_ascii() {
            res.into()
        } else {
            // TODO: This should be done with a separate PRECIS library and the preparation step of
            // the OpaqueString class should be applied first
            res.chars()
                // RFC 7613 §4.2.2:
                //    2.  Additional Mapping Rule: Any instances of non-ASCII space MUST be
                //        mapped to ASCII space (U+0020); a non-ASCII space is any Unicode
                //        code point having a Unicode general category of "Zs" (with the
                //        exception of U+0020).
                .map(|c| if c.is_whitespace() { '\u{0020}' } else { c })
                // RFC 7613 §4.2.2:
                //    4.  Normalization Rule: Unicode Normalization Form C (NFC) MUST be
                //        applied to all characters.
                .nfc()
                .collect()
        };
        match res.len() {
            0 => Err(Error::EmptyResource),
            r if r > 1023 => Err(Error::LongResource),
            _ => Ok(res),
        }
    }

    /// Construct a JID containing only a domain part.
    ///
    /// # Errors
    ///
    /// If domain fails the IDNA "to Unicode" operation, or is enclosed in square brackets ("[]")
    /// but is not a valid IPv6 address, this function returns an [error variant].
    ///
    /// [error variant]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_domain("example.net")?;
    /// assert_eq!(j, "example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn from_domain(domain: &'a str) -> Result<Jid<'a>> {
        Jid::new(None, domain, None)
    }

    /// Consumes a JID to construct a bare JID (a JID without a resourcepart).
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::new("feste", "example.net", "res")?;
    /// assert_eq!(j.bare(), "feste@example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn bare(self) -> Jid<'a> {
        Jid {
            local: self.local,
            domain: self.domain,
            resource: None,
        }
    }

    /// Consumes a JID to construct a JID with only the domainpart.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::new("feste", "example.net", "res")?;
    /// assert_eq!(j.domain(), "example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn domain(self) -> Jid<'a> {
        Jid {
            local: None,
            domain: self.domain,
            resource: None,
        }
    }

    /// Consumes a JID to construct a new JID with the given localpart.
    ///
    /// # Errors
    ///
    /// If the localpart is too long [`Error::LongLocal`] is returned.
    ///
    /// [`Error::LongLocal`]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("example.net")?;
    /// assert_eq!(j.with_local("feste")?, "feste@example.net");
    ///
    /// let j = Jid::from_str("iago@example.net")?;
    /// assert_eq!(j.with_local(None)?, "example.net");
    ///
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert!(j.with_local("").is_err());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_local<T: Into<Option<&'a str>>>(self, local: T) -> Result<Jid<'a>> {
        Ok(Jid {
            local: match local.into() {
                Some(l) => Some(Jid::process_local(l)?),
                None => None,
            },
            domain: self.domain,
            resource: self.resource,
        })
    }

    /// Consumes a JID to construct a new JID with the given domainpart.
    ///
    /// # Errors
    ///
    /// If the domain is too long, too short, or fails IDNA processing, an [error variant] is
    /// returned.
    ///
    /// [error variant]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert_eq!(j.with_domain("example.org")?, "feste@example.org");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_domain(self, domain: &'a str) -> Result<Jid<'a>> {
        Ok(Jid {
            local: self.local,
            domain: match Jid::process_domain(domain) {
                Err(err) => return Err(err),
                Ok(d) => d,
            },
            resource: self.resource,
        })
    }

    /// Consumes a JID to construct a new JID with the given resourcepart.
    ///
    /// # Errors
    ///
    /// If the resource is too long [`Error::LongResource`] is returned.
    ///
    /// [`Error::LongResource`]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # use xmpp_addr::Error;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert_eq!(j.with_resource("1234")?, "feste@example.net/1234");
    ///
    /// let j = Jid::from_str("feste@example.net/1234")?;
    /// assert_eq!(j.with_resource(None)?, "feste@example.net");
    ///
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert!(j.with_resource("").is_err());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_resource<T: Into<Option<&'a str>>>(self, resource: T) -> Result<Jid<'a>> {
        Ok(Jid {
            local: self.local,
            domain: self.domain,
            resource: match resource.into() {
                Some(r) => Some(Jid::process_resource(r)?),
                None => None,
            },
        })
    }

    /// Parse a string to create a Jid.
    ///
    /// This does not implement the `FromStr` trait because the Jid type requires an explicit
    /// lifetime annotation and the `from_str` method of `FromStr` uses an implicit annotation
    /// which is not compatible with the Jid type.
    ///
    /// # Errors
    ///
    /// If the entire string or any part of the JID is empty or not valid, or the domainpart fails
    /// IDNA processing or is not a valid IPv6 address, this function returns an [error variant].
    ///
    /// [error variant]: ./enum.Error.html
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("juliet@example.net/balcony")?;
    /// assert_eq!(j, "juliet@example.net/balcony");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn from_str(s: &'a str) -> Result<Jid<'a>> {
        let (lpart, dpart, rpart) = Jid::split(s)?;
        Jid::new(lpart, dpart, rpart)
    }

    /// Returns the localpart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("mercutio@example.net/rp")?;
    /// assert_eq!(j.localpart(), Some("mercutio"));
    ///
    /// let j = Jid::from_str("example.net/rp")?;
    /// assert!(j.localpart().is_none());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn localpart(&self) -> Option<&str> {
        match self.local {
            None => None,
            Some(ref l) => Some(&l[..]),
        }
    }

    /// Returns the domainpart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("mercutio@example.net/rp")?;
    /// assert_eq!(j.domainpart(), "example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn domainpart(&self) -> &str {
        &(self.domain)
    }

    /// Returns the resourcepart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("example.net/rp")?;
    /// assert_eq!(j.resourcepart(), Some("rp"));
    ///
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert!(j.resourcepart().is_none());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn resourcepart(&self) -> Option<&str> {
        match self.resource {
            None => None,
            Some(ref r) => Some(&r[..]),
        }
    }

    /// Constructs a JID from its constituent parts, bypassing safety checks.
    /// A `None` value for the localpart or resourcepart indicates that there is no localpart or
    /// resourcepart. A value of `Some("")` (although note that the `Some()` wrapper may be elided)
    /// indicates that the localpart or resourcepart is empty, which is invalid, but allowed by
    /// this unsafe function (eg. `@example.com`).
    ///
    /// # Examples
    ///
    /// Constructing an invalid JID:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// unsafe {
    ///     let j = Jid::new_unchecked(r#"/o\"#, "[badip]", None);
    ///     assert_eq!(j.localpart(), Some(r#"/o\"#));
    ///     assert_eq!(j.domainpart(), "[badip]");
    ///     assert_eq!(j.resourcepart(), None);
    ///
    ///     // Note that comparisons you would expect to work may fail when creating unsafe JIDs.
    ///     assert_ne!(j, r#"/o\@[badip]"#);
    ///
    ///     let j = Jid::new_unchecked("", "example.com", "");
    ///     assert_eq!(j, "@example.com/");
    /// }
    /// ```
    pub unsafe fn new_unchecked<L, R>(local: L, domain: &'a str, resource: R) -> Jid<'a>
    where
        L: Into<Option<&'a str>>,
        R: Into<Option<&'a str>>,
    {
        Jid {
            local: match local.into() {
                None => None,
                Some(s) => Some(s.into()),
            },
            domain: domain.into(),
            resource: match resource.into() {
                None => None,
                Some(s) => Some(s.into()),
            },
        }
    }
}

/// Format the JID in its canonical string form.
///
/// # Examples
///
/// Formatting and printing:
///
/// ```rust
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j = Jid::from_str("viola@example.net")?;
///
/// assert_eq!(format!("{}", j), "viola@example.net");
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
impl<'a> fmt::Display for Jid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.local {
            None => {}
            Some(ref l) => write!(f, "{}@", l)?,
        }
        write!(f, "{}", self.domain)?;
        match self.resource {
            None => {}
            Some(ref r) => write!(f, "/{}", r)?,
        }
        Ok(())
    }
}

/// Create a bare JID from a 2-tuple.
///
/// # Errors
///
/// If the first item in the tuple is not a valid localpart or the second item in the tuple fails
/// IDNA processing or is not a valid IPv6 address, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::{Jid, Result};
/// # fn try_main() -> std::result::Result<(), xmpp_addr::Error> {
/// let j: Jid = ("mercutio", "example.net").try_into()?;
/// assert_eq!(j, "mercutio@example.net");
///
/// let j: Result<Jid> = ("", "example.net").try_into();
/// assert!(j.is_err());
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(&'a str, &'a str)> for Jid<'a> {
    type Error = Error;

    fn try_from(parts: (&'a str, &'a str)) -> result::Result<Self, Self::Error> {
        Jid::new(Some(parts.0), parts.1, None)
    }
}

/// Create a bare JID from a 2-tuple where the localpart is optional.
///
/// # Errors
///
/// If the first item in the tuple is not a valid localpart or the second item in the tuple fails
/// IDNA processing or is not a valid IPv6 address, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::{Jid, Result};
/// # fn try_main() -> std::result::Result<(), xmpp_addr::Error> {
/// let j: Jid = (Some("mercutio"), "example.net").try_into()?;
/// assert_eq!(j, "mercutio@example.net");
///
/// let j: Jid = (None, "example.net").try_into()?;
/// assert_eq!(j, "example.net");
///
/// let j: Result<Jid> = (Some(""), "example.net").try_into();
/// assert!(j.is_err());
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(Option<&'a str>, &'a str)> for Jid<'a> {
    type Error = Error;

    fn try_from(parts: (Option<&'a str>, &'a str)) -> result::Result<Self, Self::Error> {
        Jid::new(parts.0, parts.1, None)
    }
}

/// Create a JID with a domain and resourcepart from a 2-tuple where the resourcepart is optional.
/// Generally speaking, this is not as useful as the other `TryFrom` implementatoins, but is
/// included for completenesses sake or for custom clustering implementations.
///
/// # Errors
///
/// If the first item in the tuplefails IDNA processing or is not a valid IPv6 address or the
/// second item in the tuple is not a valid resourcepart, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::{Jid, Result};
/// # fn try_main() -> std::result::Result<(), xmpp_addr::Error> {
/// let j: Jid = ("example.net", Some("node1432")).try_into()?;
/// assert_eq!(j, "example.net/node1432");
///
/// let j: Jid = ("example.net", None).try_into()?;
/// assert_eq!(j, "example.net");
///
/// let j: Result<Jid> = ("example.net", Some("")).try_into();
/// assert!(j.is_err());
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(&'a str, Option<&'a str>)> for Jid<'a> {
    type Error = Error;

    fn try_from(parts: (&'a str, Option<&'a str>)) -> result::Result<Self, Self::Error> {
        Jid::new(None, parts.0, parts.1)
    }
}

/// Creates a full JID from a 3-tuple.
///
/// # Errors
///
/// If the first item in the tuple is not a valid localpart, the second item in the tuple fails
/// IDNA processing or is not a valid IPv6 address, or the third item in the tuple is not a valid
/// domainpart, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::{Jid, Result};
/// # fn try_main() -> std::result::Result<(), xmpp_addr::Error> {
/// let j: Jid = ("mercutio", "example.net", "nctYeCzm").try_into()?;
/// assert_eq!(j, "mercutio@example.net/nctYeCzm");
///
/// let j: Result<Jid> = ("mercutio", "example.net", "").try_into();
/// assert!(j.is_err());
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(&'a str, &'a str, &'a str)> for Jid<'a> {
    type Error = Error;

    fn try_from(parts: (&'a str, &'a str, &'a str)) -> result::Result<Self, Self::Error> {
        Jid::new(Some(parts.0), parts.1, Some(parts.2))
    }
}

/// Creates a full JID from a 3-tuple where the localpart and resourcepart are optional.
///
/// # Errors
///
/// If the first item in the tuple is not a valid localpart, the second item in the tuple fails
/// IDNA processing or is not a valid IPv6 address, or the third item in the tuple is not a valid
/// domainpart, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::{Jid, Result};
/// # fn try_main() -> std::result::Result<(), xmpp_addr::Error> {
/// let j: Jid = (Some("mercutio"), "example.net", Some("nctYeCzm")).try_into()?;
/// assert_eq!(j, "mercutio@example.net/nctYeCzm");
///
/// let j: Jid = (Some("mercutio"), "example.net", None).try_into()?;
/// assert_eq!(j, "mercutio@example.net");
///
/// let j: Result<Jid> = (Some("mercutio"), "example.net", Some("")).try_into();
/// assert!(j.is_err());
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(Option<&'a str>, &'a str, Option<&'a str>)> for Jid<'a> {
    type Error = Error;

    fn try_from(
        parts: (Option<&'a str>, &'a str, Option<&'a str>),
    ) -> result::Result<Self, Self::Error> {
        Jid::new(parts.0, parts.1, parts.2)
    }
}

/// Parse a string to create a JID.
///
/// # Errors
///
/// If the entire string or any part of the JID is empty or not valid, or the domainpart fails IDNA
/// processing or is not a valid IPv6 address, this function returns an [error variant].
///
/// [error variant]: ./enum.Error.html
///
/// # Examples
///
#[cfg_attr(feature = "stable", doc = " ```rust,ignore")]
#[cfg_attr(not(feature = "stable"), doc = " ```rust")]
/// #![feature(try_from)]
/// # use std::convert::TryInto;
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j: Jid = "example.net/rp".try_into()?;
/// assert_eq!(j, "example.net/rp");
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<&'a str> for Jid<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> result::Result<Self, Self::Error> {
        Jid::from_str(s)
    }
}

/// Creates a JID from an IPv4 address.
impl<'a> convert::From<net::Ipv4Addr> for Jid<'a> {
    fn from(addr: net::Ipv4Addr) -> Jid<'a> {
        return Jid {
            local: None,
            domain: format!("{}", addr).into(),
            resource: None,
        };
    }
}

/// Creates a JID from an IPv6 address.
impl<'a> convert::From<net::Ipv6Addr> for Jid<'a> {
    fn from(addr: net::Ipv6Addr) -> Jid<'a> {
        return Jid {
            local: None,
            domain: format!("[{}]", addr).into(),
            resource: None,
        };
    }
}

/// Creates a JID from an IP address.
impl<'a> convert::From<net::IpAddr> for Jid<'a> {
    fn from(addr: net::IpAddr) -> Jid<'a> {
        match addr {
            net::IpAddr::V6(v6) => v6.into(),
            net::IpAddr::V4(v4) => v4.into(),
        }
    }
}

/// Allows JIDs to be compared with strings.
///
/// **This is expensive**. The JID is first converted into its canonical string representation and
/// compared for bit-string identity with the provided string (byte-wise compare). If the string
/// does not match, it is then canonicalized itself (by converting it into a JID) and compared
/// again. If constructing a JID from the string fails, the comparison always fails (even if the
/// original JID is would match the invalid output). Unsafe comparisons should convert the JID to a
/// string and compare strings themselves.
///
/// # Examples
///
/// ```rust
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j = Jid::from_str("example.net/rp")?;
/// assert!(j == "example.net/rp");
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
impl<'a> cmp::PartialEq<str> for Jid<'a> {
    fn eq(&self, other: &str) -> bool {
        if match Jid::split(other) {
            Err(_) => false,
            Ok(p) => {
                let local_match = match p.0 {
                    None => self.local.is_none(),
                    Some(s) => {
                        match (&self).local {
                            None => false,
                            Some(ref l) => s == l,
                        }
                    }
                };
                let res_match = match p.2 {
                    None => self.resource.is_none(),
                    Some(s) => {
                        match (&self).resource {
                            None => false,
                            Some(ref r) => s == r,
                        }
                    }
                };
                local_match && p.1 == self.domain && res_match
            }
        }
        {
            return true;
        }
        match Jid::from_str(other) {
            Ok(j) => j.eq(self),
            Err(_) => false,
        }
    }
}

/// Allows JIDs to be compared with strings.
///
/// **This is expensive**. The JID is first converted into its canonical string representation and
/// compared for bit-string identity with the provided string (byte-wise compare). If the string
/// does not match, it is then canonicalized itself (by converting it into a JID) and compared
/// again. If constructing a JID from the string fails, the comparison always fails (even if the
/// original JID is would match the invalid output). Unsafe comparisons should convert the JID to a
/// string and compare strings themselves.
///
/// # Examples
///
/// ```rust
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j = Jid::from_str("example.net/rp")?;
/// assert!("example.net/rp" == j);
/// #     Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
impl<'a> cmp::PartialEq<Jid<'a>> for str {
    fn eq(&self, other: &Jid<'a>) -> bool {
        PartialEq::eq(other, self)
    }
}

// Macro from collections::strings
macro_rules! impl_eq {
    ($lhs:ty, $rhs: ty) => {

        /// Allows JIDs to be compared with strings.
        ///
        /// **This is expensive**. The JID is first converted into its canonical string
        /// representation and compared for bit-string identity with the provided string (byte-wise
        /// compare). If the string does not match, it is then canonicalized itself (by converting
        /// it into a JID) and compared again. If constructing a JID from the string fails, the
        /// comparison always fails (even if the original JID is would match the invalid output).
        /// Unsafe comparisons should convert the JID to a string and compare strings themselves.
        impl<'a, 'b> PartialEq<$lhs> for $rhs {
            #[inline]
            fn eq(&self, other: &$lhs) -> bool { PartialEq::eq(self, &other[..]) }
        }

        /// Allows JIDs to be compared with strings.
        ///
        /// **This is expensive**. The JID is first converted into its canonical string
        /// representation and compared for bit-string identity with the provided string (byte-wise
        /// compare). If the string does not match, it is then canonicalized itself (by converting
        /// it into a JID) and compared again. If constructing a JID from the string fails, the
        /// comparison always fails (even if the original JID is would match the invalid output).
        /// Unsafe comparisons should convert the JID to a string and compare strings themselves.
        impl<'a, 'b> PartialEq<$rhs> for $lhs {
            #[inline]
            fn eq(&self, other: &$rhs) -> bool { PartialEq::eq(&self[..], other) }
        }

    }
}

impl_eq! { borrow::Cow<'b, str>, Jid<'a> }
impl_eq! { &'b str, Jid<'a> }
impl_eq! { String, Jid<'a> }
