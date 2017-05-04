//! Implements the XMPP Address Format as defined in RFC 7622.
//!
//! Historically, XMPP addresses were called "Jabber Identifiers", or JIDs.
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
//! use xmpp_jid::JID;
//!
//! let j = JID::new("feste", "example.net", "").unwrap();
//! assert_eq!(j.to_string(), "feste@example.net");
//! ```
//!
//! ## Parsing (nightly)
//!
//! #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
//! #[cfg_attr(not(feature = "stable"), doc = "```rust")]
//! #![feature(try_from)]
//! use std::convert::TryFrom;
//! use xmpp_jid::JID;
//!
//! let j = JID::try_from("juliet@example.net/balcony").unwrap();
//! assert_eq!(j.local().unwrap(), "juliet");
//! assert_eq!(j.domain(), "example.net");
//! assert_eq!(j.resource().unwrap(), "balcony");
//! ```

#![deny(missing_docs)]

#![cfg_attr(not(feature = "stable"), feature(try_from))]

#![doc(html_root_url = "https://docs.rs/xmpp-jid/0.2.5")]

extern crate idna;

#[cfg(not(feature = "stable"))]
use std::convert;

use std::borrow;
use std::fmt;
use std::net;
use std::result;
use std::str;
use std::str::FromStr;

/// Possible error values that can occur when parsing JIDs.
#[derive(Debug)]
pub enum Error {
    /// Returned if an empty string is being parsed.
    EmptyJID,

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JID<'a> {
    local: borrow::Cow<'a, str>,
    domain: borrow::Cow<'a, str>,
    resource: borrow::Cow<'a, str>,
}

impl<'a> JID<'a> {
    /// Constructs a JID from its constituent parts. The localpart is generally the username of a
    /// user on a particular server, the domainpart is a domain, hostname, or IP address where the
    /// user or entity resides, and the resourcepart identifies a specific client. Everything but
    /// the domain is optional.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// use xmpp_jid::JID;
    ///
    /// let j = JID::new("feste", "example.net", "").unwrap();
    /// assert_eq!(j.to_string(), "feste@example.net");
    /// ```
    pub fn new(local: &'a str, domain: &'a str, resource: &'a str) -> Result<JID<'a>> {

        let (dlabel, result) = idna::domain_to_unicode(domain);
        match result {
            Ok(_) => {}
            Err(e) => {
                // Ignore errors if this is a valid IPv6 address.
                if dlabel.len() > 2 && dlabel.starts_with('[') && dlabel.ends_with(']') {
                    let inner = unsafe { (&dlabel).slice_unchecked(1, dlabel.len() - 1) };
                    match net::Ipv6Addr::from_str(inner) {
                        Ok(_) => {}
                        Err(v) => return Err(Error::Addr(v)),
                    }
                } else {
                    return Err(Error::IDNA(e));
                }
            }
        }

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

        Ok(JID {
               local: local.into(),
               domain: dlabel.into(),
               resource: resource.into(),
           })
    }

    /// Parse a string to create a JID.
    pub fn parse(s: &'a str) -> Result<JID<'a>> {
        if s == "" {
            return Err(Error::EmptyJID);
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
        JID::new(lpart, dpart.trim_right_matches('.'), rpart)
    }

    /// Returns the localpart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
    /// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
    /// #![feature(try_from)]
    /// use std::convert::TryFrom;
    /// use xmpp_jid::JID;
    ///
    /// let j = JID::try_from("mercutio@example.net/rp").unwrap();
    /// assert_eq!(j.local().unwrap(), "mercutio");
    ///
    /// let j = JID::try_from("example.net/rp").unwrap();
    /// assert!(j.local().is_none());
    /// ```
    pub fn local(&self) -> Option<String> {
        let l: String = self.local.clone().into();
        match l.len() {
            0 => None,
            _ => Some(l),
        }
    }

    /// Returns the domainpart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
    /// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
    /// #![feature(try_from)]
    /// use std::convert::TryFrom;
    /// use xmpp_jid::JID;
    ///
    /// let j = JID::try_from("mercutio@example.net/rp").unwrap();
    /// assert_eq!(j.domain(), "example.net");
    /// ```
    pub fn domain(&self) -> String {
        self.domain.clone().into()
    }

    /// Returns the resourcepart of the JID in canonical form.
    ///
    /// # Examples
    ///
    /// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
    /// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
    /// #![feature(try_from)]
    /// use std::convert::TryFrom;
    /// use xmpp_jid::JID;
    ///
    /// let j = JID::try_from("example.net/rp").unwrap();
    /// assert_eq!(j.resource().unwrap(), "rp");
    ///
    /// let j = JID::try_from("feste@example.net").unwrap();
    /// assert!(j.resource().is_none());
    /// ```
    pub fn resource(&self) -> Option<String> {
        let r: String = self.resource.clone().into();
        match r.len() {
            0 => None,
            _ => Some(r),
        }
    }

    /// Constructs a JID from its constituent parts, bypassing safety checks.
    ///
    /// # Examples
    ///
    /// Constructing an invalid JID:
    ///
    /// ```rust
    /// use xmpp_jid::JID;
    ///
    /// unsafe {
    ///     let j = JID::new_unchecked(r#"/o\"#, "[badip]", "");
    ///     assert_eq!(j.to_string(), r#"/o\@[badip]"#);
    /// }
    /// ```
    pub unsafe fn new_unchecked(local: &'a str, domain: &'a str, resource: &'a str) -> JID<'a> {
        JID {
            local: local.into(),
            domain: domain.into(),
            resource: resource.into(),
        }
    }
}

/// Format the JID in its canonical string form.
impl<'a> fmt::Display for JID<'a> {
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
/// # Examples
///
/// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
/// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
/// #![feature(try_from)]
/// use std::convert::TryFrom;
/// use xmpp_jid::JID;
///
/// let j = JID::try_from(("mercutio", "example.net")).unwrap();
/// let j2 = JID::try_from("mercutio@example.net").unwrap();
/// assert_eq!(j, j2);
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(&'a str, &'a str)> for JID<'a> {
    type Error = Error;

    fn try_from(parts: (&'a str, &'a str)) -> result::Result<Self, Self::Error> {
        JID::new(parts.0, parts.1, "")
    }
}

/// Creates a full JID from a 3-tuple.
///
/// # Examples
///
/// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
/// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
/// #![feature(try_from)]
/// use std::convert::TryFrom;
/// use xmpp_jid::JID;
///
/// let j = JID::try_from(("mercutio", "example.net", "nctYeCzm")).unwrap();
/// let j2 = JID::try_from("mercutio@example.net/nctYeCzm").unwrap();
/// assert_eq!(j, j2);
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<(&'a str, &'a str, &'a str)> for JID<'a> {
    type Error = Error;

    fn try_from(parts: (&'a str, &'a str, &'a str)) -> result::Result<Self, Self::Error> {
        JID::new(parts.0, parts.1, parts.2)
    }
}

/// Parse a string to create a JID.
///
/// # Examples
///
/// #[cfg_attr(feature = "stable", doc = "```rust,no_run")]
/// #[cfg_attr(not(feature = "stable"), doc = "```rust")]
/// #![feature(try_from)]
/// use std::convert::TryFrom;
/// use xmpp_jid::JID;
///
/// let j = JID::try_from("example.net/rp").unwrap();
/// assert!(j.local().is_none());
/// assert_eq!(j.domain(), "example.net");
/// assert_eq!(j.resource().unwrap(), "rp");
/// ```
#[cfg(not(feature = "stable"))]
impl<'a> convert::TryFrom<&'a str> for JID<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> result::Result<Self, Self::Error> {
        JID::parse(s)
    }
}
