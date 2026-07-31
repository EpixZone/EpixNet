//! Epix tracker (`epix://`) announce: query a tracker peer for xite peers.
//!
//! The announce rides the EDX `Req::Announce` message as an opaque postcard
//! payload ([`crate::tracker_pc`]). This crate owns the payload but not the
//! link: the caller injects an [`AnnounceSender`], so `epix-discovery` needs no
//! transport or runtime dependency (the same seam the DHT uses for `Kad`).

use crate::tracker_pc;
use epix_core::{Error, PeerAddr, Result};

/// Signs a tracker's onion-ownership challenge with the onion identity key.
///
/// Bootstrapper-lineage trackers don't take an onion self-advert at face
/// value: the first announce comes back with an `onion_sign_this` nonce, and
/// the onion is only registered once a re-announce proves key ownership with
/// `onion_signs` (`{identity pubkey: ed25519 signature over the nonce}`).
/// Without that second step the tracker silently drops the onion - the
/// announce "succeeds" but no other node can ever discover us.
pub trait OnionSigner: Send + Sync {
    /// The onion's 32-byte ed25519 identity public key (the key encoded in
    /// the `.onion` address itself).
    fn public_key(&self) -> [u8; 32];
    /// A standard Ed25519 signature over `msg` by the identity key.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// Carries one announce payload to a tracker and returns its reply payload.
/// Implemented by whoever owns the EDX client (the runtime), so this crate
/// stays transport-free. Every failure - unreachable tracker, dead link,
/// timeout, tracker-side error - is `Err`; the caller moves to the next
/// tracker either way.
#[async_trait::async_trait]
pub trait AnnounceSender: Send + Sync {
    async fn send(&self, tracker: &PeerAddr, payload: Vec<u8>) -> std::result::Result<Vec<u8>, String>;
}

/// Parameters for an `announce` request.
pub struct AnnounceParams<'a> {
    /// Xite tracker hashes (`sha256(address)`) to query.
    pub hashes: &'a [[u8; 32]],
    /// Our fileserver port (0 if not accepting inbound).
    pub port: u16,
    /// IP types we want back, e.g. `["ipv4", "ipv6", "onion", "i2p"]`.
    pub need_types: &'a [&'a str],
    /// Max peers per xite.
    pub need_num: i64,
    /// Types the tracker should record us under (`onion`/`i2p`/`ipv4`...).
    pub add: &'a [&'a str],
    /// Our onion self-addresses (b32 host, no `.onion`), one per hash or shared,
    /// so onion-capable trackers advertise us.
    pub onions: &'a [String],
    /// Our i2p self-addresses (b32 host, no `.i2p`, e.g. `<b32>.b32`), so i2p
    /// trackers advertise us.
    pub i2p: &'a [String],
    /// Answers the tracker's `onion_sign_this` challenge, proving we own the
    /// onions in `onions`. Without it the tracker never registers them.
    pub onion_signer: Option<&'a dyn OnionSigner>,
}

/// Announce to an Epix tracker and return the peers it knows.
///
/// Two calls when the tracker challenges our onion advert: the first returns
/// the peers plus an `onion_sign_this` nonce, the second proves onion
/// ownership so the tracker actually registers us. The second call asks for no
/// peers and its failure never costs us the ones the first already handed back.
pub async fn discover_via_epix_tracker(
    sender: &dyn AnnounceSender,
    tracker: &PeerAddr,
    params: &AnnounceParams<'_>,
) -> Result<Vec<PeerAddr>> {
    let req = tracker_pc::encode_request(&tracker_pc::build_request(params))?;
    let reply = sender.send(tracker, req).await.map_err(Error::Protocol)?;
    let parsed = tracker_pc::parse_reply(&reply)?;

    if let Some(challenge) = &parsed.onion_sign_this {
        if let Some(signed) = tracker_pc::build_signed_request(params, challenge) {
            if let Ok(bytes) = tracker_pc::encode_request(&signed) {
                // Registration only: a failure here shouldn't cost us the peers
                // the first reply handed back.
                let _ = sender.send(tracker, bytes).await;
            }
        }
    }
    Ok(parsed.peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker_pc::{AnnounceResp, PeerBuckets};
    use std::sync::Mutex;

    struct FakeSigner;
    impl OnionSigner for FakeSigner {
        fn public_key(&self) -> [u8; 32] {
            [7; 32]
        }
        fn sign(&self, _msg: &[u8]) -> [u8; 64] {
            [8; 64]
        }
    }

    /// A tracker that challenges the onion advert on the first call and
    /// records every payload it was sent.
    struct ChallengingTracker {
        seen: Mutex<Vec<tracker_pc::AnnounceReq>>,
    }

    #[async_trait::async_trait]
    impl AnnounceSender for ChallengingTracker {
        async fn send(
            &self,
            _tracker: &PeerAddr,
            payload: Vec<u8>,
        ) -> std::result::Result<Vec<u8>, String> {
            let req = tracker_pc::decode_request(&payload).map_err(|e| e.to_string())?;
            let first = {
                let mut seen = self.seen.lock().unwrap();
                seen.push(req);
                seen.len() == 1
            };
            let resp = AnnounceResp {
                peers: vec![PeerBuckets {
                    ipv4: vec![vec![1, 2, 3, 4, 0x67, 0x2B]],
                    ..Default::default()
                }],
                onion_sign_this: if first { "prove-it".into() } else { String::new() },
                error: String::new(),
            };
            tracker_pc::encode_reply(&resp).map_err(|e| e.to_string())
        }
    }

    fn params<'a>(
        hashes: &'a [[u8; 32]],
        onions: &'a [String],
        signer: Option<&'a dyn OnionSigner>,
    ) -> AnnounceParams<'a> {
        AnnounceParams {
            hashes,
            port: 26552,
            need_types: &["ipv4", "onion"],
            need_num: 20,
            add: &["onion"],
            onions,
            i2p: &[],
            onion_signer: signer,
        }
    }

    /// The challenge-sign flow is two calls: peers come back on the first, the
    /// second only proves onion ownership. Losing it means the tracker never
    /// registers our onion and nobody can find us.
    #[tokio::test]
    async fn a_challenge_triggers_a_second_signed_announce() {
        let signer = FakeSigner;
        let hashes = [[5u8; 32]];
        let onions = ["aaaabbbbccccdddd".to_string()];
        let tracker = ChallengingTracker { seen: Mutex::new(Vec::new()) };
        let addr = PeerAddr::parse("127.0.0.1:26552").unwrap();

        let peers =
            discover_via_epix_tracker(&tracker, &addr, &params(&hashes, &onions, Some(&signer)))
                .await
                .unwrap();
        assert_eq!(peers, vec![PeerAddr::parse("1.2.3.4:11111").unwrap()]);

        let seen = tracker.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "challenge answered with a second announce");
        assert!(seen[0].onion_signs.is_empty());
        assert_eq!(seen[0].need_num, 20);
        assert_eq!(seen[1].onion_sign_this, "prove-it");
        assert_eq!(seen[1].onion_signs[0].0, [7u8; 32].to_vec());
        assert_eq!(seen[1].need_num, 0, "the second call asks for no peers");
    }

    /// No signer (or no onions) means nothing to prove: exactly one call.
    #[tokio::test]
    async fn no_signer_means_a_single_announce() {
        let hashes = [[5u8; 32]];
        let tracker = ChallengingTracker { seen: Mutex::new(Vec::new()) };
        let addr = PeerAddr::parse("127.0.0.1:26552").unwrap();
        discover_via_epix_tracker(&tracker, &addr, &params(&hashes, &[], None)).await.unwrap();
        assert_eq!(tracker.seen.lock().unwrap().len(), 1);
    }

    /// An unreachable tracker fails the call rather than reporting zero peers,
    /// so the announcer can back it off.
    #[tokio::test]
    async fn a_dead_tracker_is_an_error() {
        struct Dead;
        #[async_trait::async_trait]
        impl AnnounceSender for Dead {
            async fn send(
                &self,
                _t: &PeerAddr,
                _p: Vec<u8>,
            ) -> std::result::Result<Vec<u8>, String> {
                Err("EDX dial timed out".into())
            }
        }
        let hashes = [[5u8; 32]];
        let addr = PeerAddr::parse("127.0.0.1:26552").unwrap();
        let err = discover_via_epix_tracker(&Dead, &addr, &params(&hashes, &[], None))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("EDX dial timed out"));
    }
}
