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
//! perform the PRECIS ([RFC 7564]) enforcement step and it only compiles on nightly versions of
//! Rust.
//!
//! [RFC 7622]: https://tools.ietf.org/html/rfc7622
//! [RFC 7564]: https://tools.ietf.org/html/rfc7564
//!
//!
//! # Examples
//!
//! ## Basic usage
//!
//! ```rust
//! # use xmpp_addr::Jid;
//! # fn try_main() -> Result<(), xmpp_addr::Error> {
//! let j = Jid::new("feste", "example.net", "")?;
//! assert_eq!(j, "feste@example.net");
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
//! assert_eq!(j.local().unwrap(), "juliet");
//! assert_eq!(j.domain(), "example.net");
//! assert_eq!(j.resource().unwrap(), "balcony");
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

#![doc(html_root_url = "https://docs.rs/xmpp-addr/0.5.0")]

extern crate idna;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(not(feature = "stable"))]
use std::convert;

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

/// A custom result type for JIDs that elides the Error type.
pub type Result<T> = result::Result<T, Error>;

/// A parsed JID.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Jid<'a> {
    local: &'a str,
    domain: borrow::Cow<'a, str>,
    resource: &'a str,
}

impl<'a> Jid<'a> {
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
    /// let j = Jid::new("feste", "example.net", "")?;
    /// assert_eq!(j, "feste@example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn new(local: &'a str, domain: &'a str, resource: &'a str) -> Result<Jid<'a>> {
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

        if local.len() > 1023 {
            return Err(Error::LongLocal);
        }
        if dlabel.len() > 1023 {
            return Err(Error::LongDomain);
        }
        if dlabel.len() < 1 {
            return Err(Error::ShortDomain);
        }
        if resource.len() > 1023 {
            return Err(Error::LongResource);
        }

        Ok(Jid {
               local: local,
               domain: dlabel,
               resource: resource,
           })
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
        Jid::new("", domain, "")
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
            resource: "",
        }
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
            // No separator was found; this is a domain-only JID.
            None => ("", s, ""),
            // A '/' exists, but the domain part is too long.
            Some((i, '/')) if s.len() == i + 1 => return Err(Error::EmptyResource),
            // The resource part exists (there's a '/') but it's empty (the first '/' is the last
            // character).
            Some((i, '/')) if s.len() == i + 1 => return Err(Error::EmptyResource),
            // There is a resource part, and we did not find a localpart (the first separator found
            // was the first '/').
            Some((i, '/')) => ("", &s[0..i], &s[i + 1..]),
            // The JID starts with the '@' sign
            Some((i, '@')) if i == 0 => return Err(Error::EmptyLocal),
            // The JID has an '@' sign, but the local part is too long.
            Some((i, '@')) if i > 1023 => return Err(Error::LongLocal),
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
                // if lpart.contains(&['"', '&', '\'', '/', ':', '<', '>', '@', '`']) {
                if s[0..i].contains(&['"', '&', '\'', '/', ':', '<', '>', '@', '`'][..]) {
                    return Err(Error::ForbiddenChars);
                }
                match slash {
                    // This is a bare JID.
                    None => (&s[0..i], &s[i + 1..], ""),
                    // There is a '/', but it's immediately after the '@' (or there is a short
                    // domain part between them).
                    Some((j, _)) if j - i < 3 => return Err(Error::ShortDomain),
                    // The resource part exists (there's a '/') but it's empty.
                    Some((j, _)) if s.len() == j + 1 => return Err(Error::EmptyResource),
                    // This is a full JID.
                    Some((j, _)) => (&s[0..i], &s[i + 1..j], &s[j + 1..]),
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
        Jid::new(lpart, dpart.trim_right_matches('.'), rpart)
    }

    /// Returns the localpart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// # fn try_main() -> Result<(), xmpp_addr::Error> {
    /// let j = Jid::from_str("mercutio@example.net/rp")?;
    /// assert_eq!(j.local().unwrap(), "mercutio");
    ///
    /// let j = Jid::from_str("example.net/rp")?;
    /// assert!(j.local().is_none());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn local(&self) -> Option<&str> {
        match self.local.len() {
            0 => None,
            _ => Some(self.local),
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
    /// assert_eq!(j.domain(), "example.net");
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn domain(&self) -> &str {
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
    /// assert_eq!(j.resource().unwrap(), "rp");
    ///
    /// let j = Jid::from_str("feste@example.net")?;
    /// assert!(j.resource().is_none());
    /// #     Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn resource(&self) -> Option<&str> {
        match self.resource.len() {
            0 => None,
            _ => Some(self.resource),
        }
    }

    /// Constructs a JID from its constituent parts, bypassing safety checks.
    ///
    /// # Examples
    ///
    /// Constructing an invalid JID:
    ///
    /// ```rust
    /// # use xmpp_addr::Jid;
    /// unsafe {
    ///     let j = Jid::new_unchecked(r#"/o\"#, "[badip]", "");
    ///     assert_eq!(j, r#"/o\@[badip]"#);
    /// }
    /// ```
    pub unsafe fn new_unchecked(local: &'a str, domain: &'a str, resource: &'a str) -> Jid<'a> {
        Jid {
            local: local,
            domain: domain.into(),
            resource: resource,
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
        if self.local.len() > 0 && self.resource.len() > 0 {
            return write!(f, "{}@{}/{}", self.local, self.domain, self.resource);
        } else if self.local.len() > 0 {
            return write!(f, "{}@{}", self.local, self.domain);
        }
        write!(f, "{}/{}", self.domain, self.resource)
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
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j: Jid = ("mercutio", "example.net").try_into()?;
/// assert_eq!(j, "mercutio@example.net");
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
        Jid::new(parts.0, parts.1, "")
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
/// # use xmpp_addr::Jid;
/// # fn try_main() -> Result<(), xmpp_addr::Error> {
/// let j: Jid = ("mercutio", "example.net", "nctYeCzm").try_into()?;
/// assert_eq!(j, "mercutio@example.net/nctYeCzm");
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
        if self.to_string() == other {
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
