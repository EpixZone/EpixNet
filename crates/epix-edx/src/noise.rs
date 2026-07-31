//! Noise-XX-first clearnet encryption with node-key channel binding.
//!
//! Today's clearnet peer TCP is plaintext (the ZeroNet `crypt` slot was
//! never filled). EDX mandates Noise on `PeerAddr::Ip`: dial → magic →
//! Noise-XX → everything else inside the tunnel. No negotiation, no
//! downgrade surface. Overlay transports (Tor/I2P/Reticulum) already
//! encrypt and skip this layer entirely.
//!
//! The Noise static key is per-process; identity comes from the CHANNEL
//! BINDING: the `Hello` exchanged inside the tunnel carries a signature
//! by the node's ethsecp256k1 key over the Noise handshake hash, which
//! uniquely fingerprints this session (both sides compute it, an
//! attacker in the middle cannot produce a session with the same hash).
//! The payload also commits to the signer's [`Role`], so the two
//! directions of the handshake sign different strings and neither can be
//! reflected as the other. Without proof of possession a peer could spoof
//! a victim's node id to claim its reciprocity standing -
//! `verify_binding` is what stops that.
//!
//! Transport records: `u16-LE length ‖ noise ciphertext`, stateless
//! transport mode with per-direction implicit nonces (order = nonce), so
//! the two pump tasks share one `Arc<StatelessTransportState>`.

use std::io;
use std::sync::Arc;

use epix_transport::PeerStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The one cipher suite EDX speaks. Fixed - negotiation is a downgrade
/// surface, and every node ships the same build.
pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Max plaintext per noise record (65535 - 16 tag, rounded down).
const RECORD_PLAINTEXT: usize = 60_000;

/// How long the inbound pump waits for the next record before giving the
/// socket up. Deliberately well past the server's 300s idle reaper: a link the
/// reaper already dropped must not be kept alive by this, and a link still in
/// use must not be cut by it. This is the backstop for a transport that goes
/// quiet without ever sending FIN, where the `gone` signal alone cannot help
/// because the pump has no other wakeup source.
const IDLE_RECORD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Which side of the handshake made a binding signature. The signed
/// payload commits to it, so an initiator's signature never verifies as a
/// responder's. Without that separation both sides sign the same string,
/// and a responder can echo the dialer's own `node_pk` plus its `Hello`
/// signature back in the `HelloAck` and be accepted as that identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The dialing side, which signs its `Hello`.
    Initiator,
    /// The accepting side, which signs its `HelloAck`.
    Responder,
}

impl Role {
    fn tag(self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

/// Domain-separated payload the node key signs to bind its identity AND
/// its role to this session. The version is v2 because the role was added
/// to the payload; both sides of the protocol upgrade together, so there
/// is no v1 fallback.
pub fn binding_payload(handshake_hash: &[u8; 32], role: Role) -> String {
    let mut hex = String::with_capacity(64);
    for b in handshake_hash {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    format!("epix-edx-binding-v2:{}:{hex}", role.tag())
}

/// Sign the channel binding with the node's ethsecp256k1 key, in `role`.
/// The dialer signs its `Hello` as [`Role::Initiator`], the accepting side
/// signs its `HelloAck` as [`Role::Responder`].
pub fn sign_binding(
    handshake_hash: &[u8; 32],
    privatekey: &str,
    role: Role,
) -> io::Result<Vec<u8>> {
    epix_crypt::sign(&binding_payload(handshake_hash, role), privatekey)
        .map(String::into_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Verify a peer's binding signature against its claimed node key, in the
/// role that peer signed in. A `Hello` whose signature fails this check is
/// a spoofed identity; a `HelloAck` carrying an initiator's signature is a
/// reflection of the dialer's own identity and fails too.
pub fn verify_binding(handshake_hash: &[u8; 32], node_pk: &[u8], sig: &[u8], role: Role) -> bool {
    let Ok(address) = epix_crypt::pubkey_to_address(node_pk) else { return false };
    let Ok(sig) = std::str::from_utf8(sig) else { return false };
    epix_crypt::verify(&binding_payload(handshake_hash, role), &address, sig)
}

/// A secured stream plus the session facts the handshake produced.
pub struct Secured {
    pub stream: PeerStream,
    /// Uniquely fingerprints this session; what the binding signs.
    pub handshake_hash: [u8; 32],
    /// The peer's Noise static public key (NOT its identity - identity
    /// is the bound node key).
    pub remote_static: [u8; 32],
}

/// Run Noise-XX as the dialing side and wrap the stream.
pub async fn secure_initiator(inner: PeerStream) -> io::Result<Secured> {
    secure(inner, true).await
}

/// Run Noise-XX as the accepting side and wrap the stream.
pub async fn secure_responder(inner: PeerStream) -> io::Result<Secured> {
    secure(inner, false).await
}

fn noise_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

async fn read_record(inner: &mut PeerStream, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut len = [0u8; 2];
    inner.read_exact(&mut len).await?;
    buf.resize(u16::from_le_bytes(len) as usize, 0);
    inner.read_exact(buf).await?;
    Ok(())
}

async fn write_record(inner: &mut PeerStream, bytes: &[u8]) -> io::Result<()> {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    inner.write_all(&(bytes.len() as u16).to_le_bytes()).await?;
    inner.write_all(bytes).await?;
    inner.flush().await
}

async fn secure(mut inner: PeerStream, initiator: bool) -> io::Result<Secured> {
    let builder = snow::Builder::new(PATTERN.parse().expect("static pattern"));
    let keypair = builder.generate_keypair().map_err(noise_err)?;
    let builder = snow::Builder::new(PATTERN.parse().expect("static pattern"));
    let builder = builder.local_private_key(&keypair.private).map_err(noise_err)?;
    let mut hs = if initiator {
        builder.build_initiator().map_err(noise_err)?
    } else {
        builder.build_responder().map_err(noise_err)?
    };

    let mut out = vec![0u8; 1024];
    let mut payload = vec![0u8; 1024];
    let mut record = Vec::new();
    if initiator {
        // -> e
        let n = hs.write_message(&[], &mut out).map_err(noise_err)?;
        write_record(&mut inner, &out[..n]).await?;
        // <- e, ee, s, es
        read_record(&mut inner, &mut record).await?;
        hs.read_message(&record, &mut payload).map_err(noise_err)?;
        // -> s, se
        let n = hs.write_message(&[], &mut out).map_err(noise_err)?;
        write_record(&mut inner, &out[..n]).await?;
    } else {
        read_record(&mut inner, &mut record).await?;
        hs.read_message(&record, &mut payload).map_err(noise_err)?;
        let n = hs.write_message(&[], &mut out).map_err(noise_err)?;
        write_record(&mut inner, &out[..n]).await?;
        read_record(&mut inner, &mut record).await?;
        hs.read_message(&record, &mut payload).map_err(noise_err)?;
    }

    let handshake_hash: [u8; 32] = hs
        .get_handshake_hash()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad handshake hash len"))?;
    let remote_static: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no remote static"))?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad remote static len"))?;
    let transport = Arc::new(hs.into_stateless_transport_mode().map_err(noise_err)?);

    // Pump tasks: user's plaintext duplex <-> encrypted records on inner.
    let (user, net) = tokio::io::duplex(256 * 1024);
    let (net_read, net_write) = tokio::io::split(net);
    let (inner_read, inner_write) = tokio::io::split(inner);

    // Teardown signal, the same contract `Conn::start` uses for its own
    // reader/writer pair. The two pumps own the halves of the CALLER's stream -
    // which on the node is the registry's counting stream, holding both the
    // socket and the connection's Stats row - so nothing above this tunnel can
    // free them. The outbound pump ends when the user duplex closes (that is
    // all the EDX layer above holds), and dropping `gone_tx` then unblocks the
    // inbound pump. Without this the inbound pump parks in `read_exact` against
    // a peer that stays connected and silent, and the socket plus its registry
    // row leak for the life of the process even after the idle reaper fired.
    let (gone_tx, gone_rx) = tokio::sync::mpsc::channel::<()>(1);
    spawn_outbound_pump(net_read, inner_write, transport.clone(), gone_tx);
    spawn_inbound_pump(inner_read, net_write, transport, gone_rx);

    Ok(Secured { stream: Box::pin(user), handshake_hash, remote_static })
}

/// Outbound pump: plaintext -> records, nonce = record index. Owns the write
/// half of the caller's stream; ends when the user duplex closes, and its
/// `gone_tx` drop is what releases the inbound pump (see [`secure`]).
fn spawn_outbound_pump<R, W>(
    mut net_read: R,
    mut inner_write: W,
    ts: Arc<snow::StatelessTransportState>,
    gone_tx: tokio::sync::mpsc::Sender<()>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut plain = vec![0u8; RECORD_PLAINTEXT];
        let mut cipher = vec![0u8; RECORD_PLAINTEXT + 16];
        let mut nonce: u64 = 0;
        loop {
            let n = match net_read.read(&mut plain).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let Ok(clen) = ts.write_message(nonce, &plain[..n], &mut cipher) else { break };
            nonce += 1;
            let len_prefix = (clen as u16).to_le_bytes();
            // Deadline on the write, not just the read. A peer that stops
            // draining (full send buffer, zero window) parks this pump in
            // write_all, and a parked outbound pump is worse than a parked
            // inbound one: it holds its half of the caller's stream AND never
            // reaches the `gone_tx` drop below, so the inbound pump cannot be
            // released either and both the socket and the Stats row leak for
            // good. Bounded here so a wedged peer costs one deadline, not a fd.
            let sent = tokio::time::timeout(IDLE_RECORD_TIMEOUT, async {
                inner_write.write_all(&len_prefix).await?;
                inner_write.write_all(&cipher[..clen]).await?;
                inner_write.flush().await
            });
            if !matches!(sent.await, Ok(Ok(()))) {
                break;
            }
        }
        // Both of these matter to teardown: the shutdown is the FIN the peer
        // sees, and dropping the sender is what unblocks the inbound pump so it
        // releases the other half of the caller's stream.
        let _ = inner_write.shutdown().await;
        drop(gone_tx);
    });
}

/// Inbound pump: records -> plaintext, nonce = record index. Any tamper fails
/// the AEAD and tears the stream down. Owns the read half of the caller's
/// stream; unblocked by the outbound pump dropping `gone_rx`'s sender.
fn spawn_inbound_pump<R, W>(
    mut inner_read: R,
    mut net_write: W,
    transport: Arc<snow::StatelessTransportState>,
    mut gone_rx: tokio::sync::mpsc::Receiver<()>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut record = Vec::new();
        let mut plain = vec![0u8; RECORD_PLAINTEXT + 16];
        let mut nonce: u64 = 0;
        loop {
            let mut len = [0u8; 2];
            // Stop on a dead socket, on the tunnel above winding down, or on a
            // transport that has gone quiet without ever sending FIN (a
            // half-dead flow, a stalled circuit). The last case is why there is
            // a deadline and not just the `gone` signal: a peer can hold the
            // socket open with no wakeup source at all.
            let read_len = tokio::time::timeout(IDLE_RECORD_TIMEOUT, inner_read.read_exact(&mut len));
            let stop = tokio::select! {
                biased;
                _ = gone_rx.recv() => true,
                r = read_len => !matches!(r, Ok(Ok(_))),
            };
            if stop {
                break;
            }
            record.resize(u16::from_le_bytes(len) as usize, 0);
            let read_body =
                tokio::time::timeout(IDLE_RECORD_TIMEOUT, inner_read.read_exact(&mut record));
            if !matches!(read_body.await, Ok(Ok(_))) {
                break;
            }
            let Ok(n) = transport.read_message(nonce, &record, &mut plain) else { break };
            nonce += 1;
            // Deadline on the write, for the same reason as the outbound
            // pump's: this half of the duplex cannot be dropped on its own,
            // so a consumer above that stops reading (the duplex fills and
            // nothing drains it) parks this pump in write_all with no wakeup
            // source, and the caller's stream plus its Stats row leak.
            let wrote = tokio::time::timeout(IDLE_RECORD_TIMEOUT, net_write.write_all(&plain[..n]));
            if !matches!(wrote.await, Ok(Ok(()))) {
                break;
            }
        }
        let _ = net_write.shutdown().await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (PeerStream, PeerStream) {
        let (a, b) = tokio::io::duplex(1 << 16);
        (Box::pin(a), Box::pin(b))
    }

    async fn secured_pair() -> (Secured, Secured) {
        let (a, b) = pair();
        let (a, b) =
            tokio::join!(secure_initiator(a), secure_responder(b));
        (a.unwrap(), b.unwrap())
    }

    #[tokio::test]
    async fn handshake_and_bidirectional_data() {
        let (mut a, mut b) = secured_pair().await;
        assert_eq!(a.handshake_hash, b.handshake_hash, "both sides bind the same session");

        a.stream.write_all(b"from a").await.unwrap();
        let mut buf = [0u8; 6];
        b.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from a");

        b.stream.write_all(b"from b").await.unwrap();
        a.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from b");
    }

    #[tokio::test]
    async fn large_transfer_survives_record_chunking() {
        let (mut a, mut b) = secured_pair().await;
        let data: Vec<u8> = (0..300_000usize).map(|i| (i % 251) as u8).collect();
        let expect = data.clone();
        let writer = tokio::spawn(async move {
            a.stream.write_all(&data).await.unwrap();
            a // keep alive
        });
        let mut got = vec![0u8; expect.len()];
        b.stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expect);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_ciphertext_tears_the_stream_down() {
        // a <-> proxy <-> b, proxy flips one ciphertext byte.
        let (a_end, proxy_a) = pair();
        let (b_end, proxy_b) = pair();
        tokio::spawn(async move {
            let (mut ar, mut aw) = tokio::io::split(proxy_a);
            let (mut br, mut bw) = tokio::io::split(proxy_b);
            let a_to_b = async move {
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                loop {
                    let n = match ar.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    // Flip a byte deep in the stream (after the
                    // handshake, which for XX is ~3 records ~200 bytes).
                    for byte in buf[..n].iter_mut() {
                        total += 1;
                        if total == 400 {
                            *byte ^= 0x80;
                        }
                    }
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            };
            let b_to_a = async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match br.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if aw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(a_to_b, b_to_a);
        });

        let (a, b) = tokio::join!(secure_initiator(a_end), secure_responder(b_end));
        let (mut a, mut b) = (a.unwrap(), b.unwrap());

        // Push enough data through a->b to cross byte 400 on the wire.
        let payload = vec![7u8; 2000];
        let _ = a.stream.write_all(&payload).await;
        let mut got = vec![0u8; 2000];
        let res = b.stream.read_exact(&mut got).await;
        assert!(res.is_err(), "tampered record must not deliver plaintext");
    }

    #[tokio::test]
    async fn channel_binding_signs_and_verifies() {
        let (a, b) = secured_pair().await;
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let node_pk = epix_crypt::private_to_compressed_pubkey(priv_hex).unwrap();

        let sig = sign_binding(&a.handshake_hash, priv_hex, Role::Initiator).unwrap();
        // The peer verifies with the SAME hash (it has its own copy).
        assert!(verify_binding(&b.handshake_hash, &node_pk, &sig, Role::Initiator));

        // A different session's signature does not transfer (spoofing a
        // node id across sessions fails).
        let (c, _d) = secured_pair().await;
        assert!(!verify_binding(&c.handshake_hash, &node_pk, &sig, Role::Initiator));

        // A different key's signature fails against this node_pk.
        let other_priv = "2222222222222222222222222222222222222222222222222222222222222222";
        let bad = sign_binding(&a.handshake_hash, other_priv, Role::Initiator).unwrap();
        assert!(!verify_binding(&b.handshake_hash, &node_pk, &bad, Role::Initiator));
    }

    /// A binding signed in one role must not verify in the other. Without
    /// this the responder could echo the dialer's own node_pk and `Hello`
    /// signature back in its `HelloAck` and be accepted as that identity.
    #[tokio::test]
    async fn a_binding_does_not_transfer_between_roles() {
        let (a, b) = secured_pair().await;
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let node_pk = epix_crypt::private_to_compressed_pubkey(priv_hex).unwrap();

        // What a dialer puts in its Hello: valid as an initiator, and the
        // reflection back as a HelloAck must fail.
        let hello_sig = sign_binding(&a.handshake_hash, priv_hex, Role::Initiator).unwrap();
        assert!(verify_binding(&b.handshake_hash, &node_pk, &hello_sig, Role::Initiator));
        assert!(
            !verify_binding(&b.handshake_hash, &node_pk, &hello_sig, Role::Responder),
            "an initiator's signature must not pass as a responder's"
        );

        // And the mirror: an acceptor's HelloAck signature is not a Hello.
        let ack_sig = sign_binding(&a.handshake_hash, priv_hex, Role::Responder).unwrap();
        assert!(verify_binding(&b.handshake_hash, &node_pk, &ack_sig, Role::Responder));
        assert!(
            !verify_binding(&b.handshake_hash, &node_pk, &ack_sig, Role::Initiator),
            "a responder's signature must not pass as an initiator's"
        );
    }
}
