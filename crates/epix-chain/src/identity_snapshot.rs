//! Fresh, chain-bound identity state for security-sensitive xID consumers.

use crate::{ChainError, DomainSnapshot, Result};
use serde::{Deserialize, Serialize};

/// The exact finalized chain state that authenticated an identity snapshot.
///
/// This is absent only while the explicit legacy resolver mode is active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XidFinalityBinding {
    pub height: u64,
    pub digest: [u8; 32],
}

/// The effective status of an identity in one chain snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XidIdentityStatus {
    Active,
    Revoked,
}

/// One identity address explicitly present in the resolved chain snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XidIdentityAuth {
    pub auth_address: String,
    pub status: XidIdentityStatus,
    /// Block height recorded by the chain for revocation, or zero when absent.
    pub revoked_at: u64,
    /// Unix time recorded by the chain for revocation, or zero when absent.
    pub revoked_at_time: u64,
}

/// Every identity state proven for one canonical xID name by one fresh resolve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XidIdentitySnapshot {
    pub canonical_name: String,
    pub identities: Vec<XidIdentityAuth>,
    pub finality: Option<XidFinalityBinding>,
}

impl XidIdentitySnapshot {
    /// Return a status only when the address is explicitly present in this
    /// snapshot. An unknown local address returns `None`; callers must not infer
    /// that absence means revocation.
    pub fn status_for(&self, auth_address: &str) -> Option<XidIdentityStatus> {
        let mut found = None;
        for identity in self
            .identities
            .iter()
            .filter(|identity| identity.auth_address == auth_address)
        {
            if identity.status == XidIdentityStatus::Revoked {
                return Some(XidIdentityStatus::Revoked);
            }
            found = Some(XidIdentityStatus::Active);
        }
        found
    }
}

/// Resolve one xID name without using the resolver's domain snapshot cache.
///
/// `Ok(Some(_))` is a single chain-proven [`DomainSnapshot`] mapped together
/// with the exact finality height and digest that authenticated it. `Ok(None)`
/// is the resolver's distinct not-found answer. Transport, proof, parsing, and
/// finality failures remain `Err`, so callers cannot confuse them with either a
/// proven empty identity set or an explicit revocation.
pub async fn resolve_xid_identity_snapshot(fqdn: &str) -> Result<Option<XidIdentitySnapshot>> {
    let (name, tld, canonical_name) = canonical_xid_parts(fqdn)?;
    let resolved = crate::shared_resolver()
        .resolve_fresh_bound(&name, &tld)
        .await;
    map_resolution(&canonical_name, resolved)
}

fn canonical_xid_parts(fqdn: &str) -> Result<(String, String, String)> {
    let fqdn = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    let (name, tld) = match fqdn.rsplit_once('.') {
        Some(parts) => parts,
        None => (fqdn.as_str(), "epix"),
    };
    if name.is_empty()
        || tld != "epix"
        || name.contains('.')
        || name
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'\\' | b'?' | b'#'))
    {
        return Err(ChainError::Malformed(format!("invalid xID name `{fqdn}`")));
    }
    let name = name.to_string();
    let tld = tld.to_string();
    let canonical_name = format!("{name}.{tld}");
    Ok((name, tld, canonical_name))
}

fn map_resolution(
    canonical_name: &str,
    resolved: Result<(DomainSnapshot, Option<(u64, String)>)>,
) -> Result<Option<XidIdentitySnapshot>> {
    let (domain, binding) = match resolved {
        Ok(resolved) => resolved,
        Err(ChainError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };

    if domain.fqdn() != canonical_name {
        return Err(ChainError::Malformed(format!(
            "resolved xID snapshot is for {}, expected {canonical_name}",
            domain.fqdn()
        )));
    }

    let finality = binding.map(parse_binding).transpose()?;
    let identities = domain
        .identities
        .into_iter()
        .map(|identity| {
            let revoked =
                !identity.active || identity.revoked_at != 0 || identity.revoked_at_time != 0;
            XidIdentityAuth {
                auth_address: identity.address,
                status: if revoked {
                    XidIdentityStatus::Revoked
                } else {
                    XidIdentityStatus::Active
                },
                revoked_at: identity.revoked_at,
                revoked_at_time: identity.revoked_at_time,
            }
        })
        .collect();

    Ok(Some(XidIdentitySnapshot {
        canonical_name: canonical_name.to_string(),
        identities,
        finality,
    }))
}

fn parse_binding((height, digest_hex): (u64, String)) -> Result<XidFinalityBinding> {
    if height == 0 {
        return Err(ChainError::Malformed(
            "resolved finality binding has zero height".into(),
        ));
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(digest_hex.trim(), &mut digest).map_err(|_| {
        ChainError::Malformed("resolved finality binding digest is not 32-byte hex".into())
    })?;
    Ok(XidFinalityBinding { height, digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn domain(identities: Vec<Identity>) -> DomainSnapshot {
        DomainSnapshot {
            name: "alice".into(),
            tld: "epix".into(),
            owner: "epix1owner".into(),
            content_root: String::new(),
            identities,
            dns_records: Vec::new(),
            avatar: String::new(),
            bio: String::new(),
        }
    }

    fn identity(address: &str, active: bool, revoked_at: u64, revoked_at_time: u64) -> Identity {
        Identity {
            address: address.into(),
            label: "epixnet".into(),
            active,
            revoked_at,
            revoked_at_time,
        }
    }

    #[test]
    fn maps_every_chain_identity_and_exact_finality_binding() {
        let resolved = map_resolution(
            "alice.epix",
            Ok((
                domain(vec![
                    identity("epix1active", true, 0, 0),
                    identity("epix1inactive", false, 0, 0),
                    identity("epix1revoked", true, 42, 1_700_000_000),
                ]),
                Some((73, DIGEST.into())),
            )),
        )
        .unwrap()
        .unwrap();

        assert_eq!(resolved.canonical_name, "alice.epix");
        assert_eq!(resolved.identities.len(), 3);
        assert_eq!(resolved.identities[0].status, XidIdentityStatus::Active);
        assert_eq!(resolved.identities[1].status, XidIdentityStatus::Revoked);
        assert_eq!(resolved.identities[2].status, XidIdentityStatus::Revoked);
        assert_eq!(resolved.identities[2].revoked_at, 42);
        assert_eq!(resolved.identities[2].revoked_at_time, 1_700_000_000);
        assert_eq!(
            resolved.finality,
            Some(XidFinalityBinding {
                height: 73,
                digest: [0x11; 32],
            })
        );
    }

    #[test]
    fn unknown_local_auth_is_not_inferred_revoked() {
        let resolved = map_resolution(
            "alice.epix",
            Ok((domain(vec![identity("epix1known", false, 42, 7)]), None)),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            resolved.status_for("epix1known"),
            Some(XidIdentityStatus::Revoked)
        );
        assert_eq!(resolved.status_for("epix1unknown-local"), None);
    }

    #[test]
    fn not_found_and_transient_failures_stay_distinct() {
        assert_eq!(
            map_resolution(
                "missing.epix",
                Err(ChainError::NotFound("missing.epix".into()))
            )
            .unwrap(),
            None
        );
        assert!(matches!(
            map_resolution("alice.epix", Err(ChainError::Rpc("offline".into()))),
            Err(ChainError::Rpc(message)) if message == "offline"
        ));
    }

    #[test]
    fn canonicalizes_input_before_resolving() {
        assert_eq!(
            canonical_xid_parts("  ALICE.EPIX.  ").unwrap(),
            ("alice".into(), "epix".into(), "alice.epix".into())
        );
        assert_eq!(
            canonical_xid_parts("Alice").unwrap(),
            ("alice".into(), "epix".into(), "alice.epix".into())
        );
        assert!(canonical_xid_parts("alice.example").is_err());
        assert!(canonical_xid_parts("sub.alice.epix").is_err());
    }

    #[test]
    fn invalid_finality_binding_fails_closed() {
        assert!(matches!(
            map_resolution(
                "alice.epix",
                Ok((domain(Vec::new()), Some((0, DIGEST.into()))))
            ),
            Err(ChainError::Malformed(_))
        ));
        assert!(matches!(
            map_resolution(
                "alice.epix",
                Ok((domain(Vec::new()), Some((73, "not-a-digest".into()))))
            ),
            Err(ChainError::Malformed(_))
        ));
    }
}
