//! `epix-group-engine` — Sender-Keys group messaging over the anonymous pool.
//!
//! **Status: foundation.** This crate implements the forward-secure key-management
//! core of a Signal/WhatsApp-style *Sender Keys* group protocol, sized for the
//! metadata-private pool transport. It is deliberately independent of the pairwise
//! engine so a group of `N` no longer costs `N` fan-out records per message — one
//! member seals ONE group record that every member detects and opens.
//!
//! ## Design
//! Each member owns a per-group **[`SenderChain`]**: a forward-secure message-key
//! chain (`mk_i = MAC(ck_i, 0x01)`, `ck_{i+1} = MAC(ck_i, 0x02)`, delete `ck_i`)
//! and a parallel forward-secure **detection-tag** chain (`tag_i = MAC(dck_i,
//! "gtag")`, `dck_{i+1} = MAC(dck_i, "gchain")`), just like the pairwise engine's
//! tag chain but per-sender-in-group. A member sends by sealing under its own
//! chain; a member receives by ratcheting the *sender's* chain to the record's
//! index (storing skipped keys for out-of-order delivery, bounded by `MAX_SKIP`).
//!
//! A member bootstraps another member's receive chain by shipping its
//! [`SenderChain::bootstrap`] once over an existing **pairwise** session (that is
//! the only place the pairwise engine is used — key distribution, not per-message).
//!
//! ## Not yet (documented in `docs/channel-group-engine.md`)
//! - **Per-sender message signatures.** A group record is currently authenticated
//!   only by the sender key, which every member holds — so a member could forge a
//!   message as another member. Real Sender Keys attach a per-sender signature
//!   (public key shipped in the bootstrap). That layer, plus membership-change
//!   rekeying (the property MLS gives natively), and the node/pool wiring, are the
//!   next phase. Until then this engine must NOT gate real group confidentiality.

pub mod crypto;

use crypto::{aead_open, aead_seal, kdf, mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Largest head-of-chain gap a receive chain self-heals (matches the pairwise
/// engine); also the retained skipped-key cap.
pub const MAX_SKIP: u32 = 256;
/// Published detection-tag window (kept == `MAX_SKIP`, as in the pairwise engine).
pub const LOOKAHEAD: u32 = 256;

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("os rng");
    b
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()?.try_into().ok()
}

fn message_key(ck: &[u8; 32]) -> [u8; 32] {
    mac(ck, &[1])
}
fn next_ck(ck: &[u8; 32]) -> [u8; 32] {
    mac(ck, &[2])
}
fn tag_of(dck: &[u8; 32]) -> [u8; 32] {
    mac(dck, b"gtag")
}
fn next_dck(dck: &[u8; 32]) -> [u8; 32] {
    mac(dck, b"gchain")
}

/// A per-group, per-sender forward-secure chain (message keys + detection tags).
#[derive(Serialize, Deserialize, Clone)]
pub struct SenderChain {
    ck: [u8; 32],
    i: u32,
    dck: [u8; 32],
    tag_i: u32,
    /// Skipped `(index, message_key)` for out-of-order receive (bounded).
    skipped: Vec<(u32, [u8; 32])>,
}

impl Drop for SenderChain {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.ck.zeroize();
        self.dck.zeroize();
        for (_, k) in self.skipped.iter_mut() {
            k.zeroize();
        }
    }
}

impl SenderChain {
    /// A fresh chain (used when a member first joins / first sends to a group).
    pub fn new() -> Self {
        Self { ck: rand32(), i: 0, dck: rand32(), tag_i: 0, skipped: Vec::new() }
    }

    /// The distributable bootstrap: the chain's CURRENT start, so a peer can
    /// follow this sender from here. Ship it once over a pairwise session.
    pub fn bootstrap(&self) -> Value {
        json!({ "ck": b64(&self.ck), "i": self.i, "dck": b64(&self.dck), "tag_i": self.tag_i })
    }

    /// Rebuild a receive chain from a peer's [`Self::bootstrap`].
    pub fn from_bootstrap(v: &Value) -> Option<Self> {
        Some(Self {
            ck: b64_32(v.get("ck")?.as_str()?)?,
            i: v.get("i")?.as_u64()? as u32,
            dck: b64_32(v.get("dck")?.as_str()?)?,
            tag_i: v.get("tag_i")?.as_u64()? as u32,
            skipped: Vec::new(),
        })
    }

    /// The next `(tag, index)` for SENDING, advancing the tag chain.
    fn next_send_tag(&mut self) -> ([u8; 32], u32) {
        let tag = tag_of(&self.dck);
        let idx = self.tag_i;
        self.dck = next_dck(&self.dck);
        self.tag_i += 1;
        (tag, idx)
    }

    /// The next message key for SENDING, advancing the key chain.
    fn next_send_key(&mut self) -> ([u8; 32], u32) {
        let mk = message_key(&self.ck);
        let idx = self.i;
        self.ck = next_ck(&self.ck);
        self.i += 1;
        (mk, idx)
    }

    /// The `LOOKAHEAD` receive tags from the current position (for a recipient to
    /// register so it can detect this sender's next records).
    pub fn window_tags(&self) -> Vec<(u32, [u8; 32])> {
        let mut out = Vec::with_capacity(LOOKAHEAD as usize);
        let mut dck = self.dck;
        for k in 0..LOOKAHEAD {
            out.push((self.tag_i + k, tag_of(&dck)));
            dck = next_dck(&dck);
        }
        out
    }

    /// Derive the message key for a RECEIVED record at message index `n`,
    /// ratcheting forward (storing skipped keys) or replaying a stored skip.
    /// Fails closed if `n` is more than `MAX_SKIP` ahead. Also advances the tag
    /// chain to `n+1` so `window_tags` slides forward.
    fn recv_key(&mut self, n: u32) -> Option<[u8; 32]> {
        if let Some(pos) = self.skipped.iter().position(|(j, _)| *j == n) {
            return Some(self.skipped.remove(pos).1);
        }
        if n < self.i || self.i + MAX_SKIP < n {
            return None; // already consumed, or an absurd jump — fail closed
        }
        while self.i < n {
            let mk = message_key(&self.ck);
            self.skipped.push((self.i, mk));
            self.ck = next_ck(&self.ck);
            self.i += 1;
        }
        let overflow = self.skipped.len().saturating_sub(MAX_SKIP as usize);
        if overflow > 0 {
            self.skipped.drain(0..overflow);
        }
        let mk = message_key(&self.ck);
        self.ck = next_ck(&self.ck);
        self.i += 1;
        // Slide the tag window forward past this index.
        while self.tag_i <= n {
            self.dck = next_dck(&self.dck);
            self.tag_i += 1;
        }
        Some(mk)
    }
}

impl Default for SenderChain {
    fn default() -> Self {
        Self::new()
    }
}

fn nonce_from(mk: &[u8; 32]) -> [u8; 12] {
    let mut out = [0u8; 12];
    kdf("epix-group/nonce/v1", &[], mk, &mut out);
    out
}

/// A sealed group record: the detection `tag`, message index, and ciphertext.
#[derive(Debug, Clone)]
pub struct GroupSealed {
    pub tag: [u8; 32],
    pub index: u32,
    pub ct: Vec<u8>,
}

/// A decrypted group record + outstanding delivery gap.
#[derive(Debug, Clone)]
pub struct GroupOpened {
    pub group_id: [u8; 16],
    pub sender_xid: String,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
    pub pending: u32,
}

/// A member's view of one group: its own send chain plus a receive chain per
/// other member.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct GroupSession {
    pub group_id: [u8; 16],
    pub my_xid: String,
    own: SenderChain,
    peers: std::collections::HashMap<String, SenderChain>,
}

impl GroupSession {
    /// Start a group as `my_xid` with a fresh own send chain.
    pub fn create(group_id: [u8; 16], my_xid: &str) -> Self {
        Self {
            group_id,
            my_xid: my_xid.to_string(),
            own: SenderChain::new(),
            peers: std::collections::HashMap::new(),
        }
    }

    /// My send-chain bootstrap to hand each other member (over pairwise) so they
    /// can follow my group messages.
    pub fn my_bootstrap(&self) -> Value {
        self.own.bootstrap()
    }

    /// Install another member's send chain from their bootstrap.
    pub fn add_member(&mut self, sender_xid: &str, bootstrap: &Value) -> bool {
        match SenderChain::from_bootstrap(bootstrap) {
            Some(ch) => {
                self.peers.insert(sender_xid.to_string(), ch);
                true
            }
            None => false,
        }
    }

    /// Detection tags to register for every member's next records.
    pub fn all_recv_tags(&self) -> Vec<(String, Vec<(u32, [u8; 32])>)> {
        self.peers.iter().map(|(x, c)| (x.clone(), c.window_tags())).collect()
    }

    /// Seal an outbound group message on my own chain.
    pub fn seal(&mut self, subject: &str, body: &str, sent_ms: i64) -> GroupSealed {
        let (tag, _tag_idx) = self.own.next_send_tag();
        let (mk, index) = self.own.next_send_key();
        let payload = json!({
            "g": hex::encode(self.group_id), "f": self.my_xid, "s": subject, "b": body,
            "t": sent_ms, "n": index,
        });
        let pt = serde_json::to_vec(&payload).unwrap_or_default();
        let ct = aead_seal(&mk, &nonce_from(&mk), &tag, &pt);
        GroupSealed { tag, index, ct }
    }

    /// Open a group record from member `sender_xid` whose `tag` matched at the
    /// tag index `n` (the caller looked `tag` up in its registered window).
    pub fn open(&mut self, sender_xid: &str, n: u32, tag: &[u8; 32], ct: &[u8]) -> Option<GroupOpened> {
        let chain = self.peers.get_mut(sender_xid)?;
        let mk = chain.recv_key(n)?;
        let pt = aead_open(&mk, &nonce_from(&mk), tag, ct)?;
        let v: Value = serde_json::from_slice(&pt).ok()?;
        let pending = chain.skipped.len() as u32;
        // Attribute the message to the AUTHENTICATED chain owner it decrypted
        // under — NEVER the payload's self-declared `f`, which a member seals on
        // their own chain and could set to another member's name (author spoof).
        // Reject a payload whose declared sender disagrees, as defense in depth.
        if v.get("f").and_then(|x| x.as_str()) != Some(sender_xid) {
            return None;
        }
        Some(GroupOpened {
            group_id: hex::decode(v.get("g")?.as_str()?).ok()?.try_into().ok()?,
            sender_xid: sender_xid.to_string(),
            subject: v.get("s").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            body: v.get("b").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            sent_ms: v.get("t").and_then(|x| x.as_i64()).unwrap_or(0),
            pending,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_send_and_receive_roundtrip() {
        let gid = [1u8; 16];
        // Alice creates the group; Bob and Carol are members.
        let mut alice = GroupSession::create(gid, "alice.epix");
        let mut bob = GroupSession::create(gid, "bob.epix");
        // Bob learns Alice's send chain via the (pairwise-delivered) bootstrap.
        assert!(bob.add_member("alice.epix", &alice.my_bootstrap()));

        // Alice's registered tags for herself = what Bob registered for her.
        let (_x, alice_tags) = bob.all_recv_tags().into_iter().next().unwrap();

        let m0 = alice.seal("Party", "at 8 ZQ1", 100);
        let m1 = alice.seal("Party", "bring snacks", 200);
        // The two records are unlinkable from outside (distinct tags) and carry no
        // plaintext.
        assert_ne!(m0.tag, m1.tag);
        assert!(!m0.ct.windows(3).any(|w| w == b"ZQ1"));

        // Bob detects each via the registered window and opens in order.
        let n0 = alice_tags.iter().find(|(_, t)| *t == m0.tag).map(|(n, _)| *n).unwrap();
        let o0 = bob.open("alice.epix", n0, &m0.tag, &m0.ct).unwrap();
        assert_eq!((o0.subject.as_str(), o0.body.as_str()), ("Party", "at 8 ZQ1"));
        assert_eq!(o0.sender_xid, "alice.epix");
        assert_eq!(o0.pending, 0);

        // Bob's window slid; re-derive Alice's tags and open m1.
        let alice_tags2 = {
            let mut out = None;
            for (x, tags) in bob.all_recv_tags() {
                if x == "alice.epix" {
                    out = Some(tags);
                }
            }
            out.unwrap()
        };
        let n1 = alice_tags2.iter().find(|(_, t)| *t == m1.tag).map(|(n, _)| *n).unwrap();
        let o1 = bob.open("alice.epix", n1, &m1.tag, &m1.ct).unwrap();
        assert_eq!(o1.body, "bring snacks");
    }

    #[test]
    fn out_of_order_receive_reports_pending_and_self_heals() {
        let gid = [2u8; 16];
        let mut alice = GroupSession::create(gid, "alice.epix");
        let mut bob = GroupSession::create(gid, "bob.epix");
        bob.add_member("alice.epix", &alice.my_bootstrap());
        let tags: Vec<_> = bob.all_recv_tags().into_iter().next().unwrap().1;

        let msgs: Vec<_> = (0..5).map(|k| alice.seal("s", &format!("m{k}"), k)).collect();
        // Bob receives #3 first (skipping 0..2), then #0.
        let n3 = tags.iter().find(|(_, t)| *t == msgs[3].tag).map(|(n, _)| *n).unwrap();
        let o3 = bob.open("alice.epix", n3, &msgs[3].tag, &msgs[3].ct).unwrap();
        assert_eq!(o3.body, "m3");
        assert!(o3.pending >= 3, "earlier ones reported pending: {}", o3.pending);
        // The skipped #0 still opens later (self-heal).
        let n0 = tags.iter().find(|(_, t)| *t == msgs[0].tag).map(|(n, _)| *n).unwrap();
        let o0 = bob.open("alice.epix", n0, &msgs[0].tag, &msgs[0].ct).unwrap();
        assert_eq!(o0.body, "m0");
    }

    #[test]
    fn a_stranger_cannot_open_a_group_record() {
        let gid = [3u8; 16];
        let mut alice = GroupSession::create(gid, "alice.epix");
        let m = alice.seal("s", "secret", 1);
        // Eve has no chain for alice → cannot open.
        let mut eve = GroupSession::create(gid, "eve.epix");
        assert!(eve.open("alice.epix", 0, &m.tag, &m.ct).is_none());
    }
}
