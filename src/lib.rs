#![feature(try_from)]

#[macro_use]
extern crate serde_derive;
extern crate serde_xml_rs;

extern crate idna;

use std::borrow;
use std::convert;
use std::fmt;
use std::net;
use std::result;
use std::str;
use std::str::FromStr;

#[derive(Debug)]
pub enum Error {
    EmptyJID,
    EmptyLocal,
    LongLocal,
    ShortDomain,
    LongDomain,
    EmptyResource,
    LongResource,
    ForbiddenChars,
    Addr(net::AddrParseError),
    IDNA(idna::uts46::Errors),
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Deserialize, Debug, Clone)]
pub struct JID<'a> {
    local: borrow::Cow<'a, str>,
    domain: borrow::Cow<'a, str>,
    resource: borrow::Cow<'a, str>,
}

impl<'a> JID<'a> {
    pub fn new<L, D, R>(local: L, domain: D, resource: R) -> Result<JID<'a>>
        where L: Into<borrow::Cow<'a, str>>,
              D: Into<borrow::Cow<'a, str>>,
              R: Into<borrow::Cow<'a, str>>
    {

        let (dlabel, result) = idna::domain_to_unicode(&(domain.into()));
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

        let l = local.into();
        if l.len() > 1023 {
            return Err(Error::LongLocal);
        }
        if dlabel.len() > 1023 {
            return Err(Error::LongDomain);
        }
        if dlabel.len() < 1 {
            return Err(Error::ShortDomain);
        }
        let r = resource.into();
        if r.len() > 1023 {
            return Err(Error::LongResource);
        }

        Ok(JID {
               local: l,
               domain: borrow::Cow::from(dlabel),
               resource: r,
           })
    }

    pub fn local(&self) -> Option<String> {
        let l: String = self.local.clone().into();
        match l.len() {
            0 => None,
            _ => Some(l),
        }
    }

    pub fn domain(&self) -> String {
        self.domain.clone().into()
    }

    pub fn resource(&self) -> Option<String> {
        let r: String = self.resource.clone().into();
        match r.len() {
            0 => None,
            _ => Some(r),
        }
    }
}

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

impl<'a> convert::TryFrom<&'a str> for JID<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> result::Result<Self, Self::Error> {
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
                                 (_, '@') => true,
                                 (_, '/') => true,
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
}
