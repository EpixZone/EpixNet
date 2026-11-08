//! Versioned, xite-bound local profiles. Keys never cross the command boundary.
//! Private groups use existing ECIES independently for each authenticated member.
//! This format does not provide forward secrecy or conceal traffic metadata.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::HashSet;

pub(super) const PROTOCOL: &str = "epix-local-profile/1";
pub(super) const MAX_MEMBERS: usize = 8;
pub(super) const MAX_TEXT: usize = 4096;
pub(super) const MAX_RECORD: usize = 192 * 1024;
pub(super) const MAX_BOX: usize = 16 * 1024;

#[derive(Clone)]
pub(super) struct Keys {
    pub xite: String,
    pub author: String,
    sign: String,
    encrypt: String,
    pub public: String,
}

impl Keys {
    pub fn from_seed(seed: &str, xite: &str) -> Result<Self, String> {
        if !epix_crypt::is_valid_address(xite) {
            return Err("Invalid canonical xite".into());
        }
        let sign = epix_crypt::private_to_wif(&super::super::AppState::consumer_seed(
            seed,
            "epix/local-profile/sign/v1",
            xite,
        ));
        let encrypt = epix_crypt::private_to_wif(&super::super::AppState::consumer_seed(
            seed,
            "epix/local-profile/encrypt/v1",
            xite,
        ));
        Ok(Self {
            xite: xite.into(),
            author: epix_crypt::privatekey_to_address(&sign)?,
            public: hex::encode(epix_crypt::private_to_compressed_pubkey(&encrypt)?),
            sign,
            encrypt,
        })
    }

    pub fn manifest_sign(&self, value: &mut Value) -> Result<(), String> {
        epix_content::sign(value, &self.sign)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn sign(&self, mut record: Value) -> Result<Value, String> {
        record["sign"] = json!(epix_crypt::sign(&signed_data(&record), &self.sign)?);
        Ok(record)
    }

    pub fn profile(&self, name: &str, old: Option<&Value>) -> Result<Value, String> {
        bounded_text(name, 80)?;
        if let Some(old) = old {
            verify_profile(old, &self.xite)?;
            if old["author"] != self.author || old["encryption_key"] != self.public {
                return Err("Stored local profile does not match this identity".into());
            }
        }
        self.sign(json!({"protocol":PROTOCOL,"kind":"profile","xite":self.xite,
            "author":self.author,"encryption_key":self.public,"display_name":name,
            "created_at":old.and_then(|v|v["created_at"].as_u64()).unwrap_or_else(|| epix_core::now_secs().max(0) as u64),
            "xid":old.and_then(|v|v.get("xid")).cloned().unwrap_or(Value::Null)}))
    }

    pub fn link(&self, profile: &Value, identity: &epix_user::Identity) -> Result<Value, String> {
        verify_profile(profile, &self.xite)?;
        let mut link = json!({"protocol":PROTOCOL,"kind":"xid-link","xite":self.xite,
            "author":identity.auth_address,"name":identity.xid(),"profile_author":self.author,
            "encryption_key":self.public});
        link["sign"] = json!(epix_crypt::sign(
            &signed_data(&link),
            &identity.auth_privatekey
        )?);
        let mut profile = profile.clone();
        profile["xid"] = link;
        self.sign(profile)
    }

    pub fn public_post(&self, profile: &Value, room: &str, text: &str) -> Result<Value, String> {
        bounded_text(room, 80)?;
        bounded_text(text, MAX_TEXT)?;
        self.sign(json!({"protocol":PROTOCOL,"kind":"public","xite":self.xite,
            "author":self.author,"id":random_id()?,"sent_at":epix_core::now_secs(),
            "room":room,"text":text,"profile":profile}))
    }

    pub fn group(&self, title: &str, profiles: &[Value], own: &Value) -> Result<Value, String> {
        bounded_text(title, 120)?;
        let mut members = profiles.to_vec();
        if !members.iter().any(|p| p["author"] == self.author) {
            members.push(own.clone());
        }
        members.sort_by(|a, b| a["author"].as_str().cmp(&b["author"].as_str()));
        let group = self.sign(json!({"protocol":PROTOCOL,"kind":"group","xite":self.xite,
            "author":self.author,"nonce":random_id()?,"title":title,"members":members}))?;
        verify_group(&group, &self.xite)?;
        Ok(group)
    }

    pub fn seal(&self, group: &Value, kind: &str, text: &str) -> Result<Value, String> {
        let members = verify_group(group, &self.xite)?;
        require_member(members, &self.author, &self.public)?;
        if kind == "message" {
            bounded_text(text, MAX_TEXT)?;
        } else if kind != "invitation" || !text.is_empty() {
            return Err("Invalid private message kind".into());
        }
        let id = random_id()?;
        let sent_at = epix_core::now_secs();
        let message = self.sign(json!({"protocol":PROTOCOL,"kind":kind,"xite":self.xite,
            "author":self.author,"id":id,"sent_at":sent_at,"text":text,
            "group_id":group_id(group),"group":group}))?;
        let plaintext = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
        if plaintext.len() > MAX_BOX - 256 {
            return Err("Private message exceeds the bounded format".into());
        }
        let mut boxes = Vec::with_capacity(members.len());
        for member in members {
            let key = hex::decode(string(member, "encryption_key")?)
                .map_err(|_| "Invalid encryption key")?;
            let (encrypted, _) = epix_crypt::ecies::ecies_encrypt(&plaintext, &key)?;
            boxes.push(STANDARD.encode(encrypted));
        }
        // Random ordering avoids exposing the canonical member ordering.
        for i in (1..boxes.len()).rev() {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|_| "Random source unavailable")?;
            boxes.swap(i, (u64::from_le_bytes(random) % (i as u64 + 1)) as usize);
        }
        self.sign(
            json!({"protocol":PROTOCOL,"kind":"private","xite":self.xite,
            "author":self.author,"id":id,"sent_at":sent_at,"boxes":boxes}),
        )
    }

    pub fn open(&self, envelope: &Value, budget: &mut usize) -> Result<Value, String> {
        verify_envelope(envelope, &self.xite)?;
        for ciphertext in envelope["boxes"].as_array().ok_or("Missing boxes")? {
            if *budget == 0 {
                return Err("Private read budget exhausted".into());
            }
            *budget -= 1;
            let blob = STANDARD
                .decode(ciphertext.as_str().ok_or("Invalid ciphertext")?)
                .map_err(|_| "Invalid ciphertext")?;
            let Ok(plaintext) = epix_crypt::ecies::ecies_decrypt(&blob, &self.encrypt) else {
                continue;
            };
            let message: Value =
                serde_json::from_slice(&plaintext).map_err(|_| "Invalid private message")?;
            self.verify_opened(&message, envelope)?;
            return Ok(message);
        }
        Err("Not a recipient".into())
    }
    fn verify_opened(&self, message: &Value, envelope: &Value) -> Result<(), String> {
        verify_signed(message, &self.xite)?;
        fields(
            message,
            &[
                "protocol", "kind", "xite", "author", "id", "sent_at", "text", "group_id", "group",
                "sign",
            ],
        )?;
        for name in ["id", "author", "sent_at"] {
            if message[name] != envelope[name] {
                return Err("Private message binding mismatch".into());
            }
        }
        let members = verify_group(&message["group"], &self.xite)?;
        require_member(members, &self.author, &self.public)?;
        if !members.iter().any(|p| p["author"] == message["author"]) {
            return Err("Sender is not a group member".into());
        }
        if message["group_id"] != group_id(&message["group"]) {
            return Err("Group binding mismatch".into());
        }
        match string(message, "kind")? {
            "message" => bounded_text(string(message, "text")?, MAX_TEXT)?,
            "invitation"
                if message["text"] == "" && message["author"] == message["group"]["author"] => {}
            _ => return Err("Invalid private message kind".into()),
        }
        Ok(())
    }
}

fn signed_data(record: &Value) -> String {
    format!(
        "epix/local-profile/record/v1\0{}",
        epix_content::record_signed_data(record)
    )
}

pub(super) fn group_id(group: &Value) -> String {
    blake3::hash(signed_data(group).as_bytes())
        .to_hex()
        .to_string()
}

fn verify_signed(record: &Value, xite: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_RECORD || record["protocol"] != PROTOCOL || record["xite"] != xite {
        return Err("Invalid local profile scope or size".into());
    }
    let author = string(record, "author")?;
    let signature = string(record, "sign")?;
    if !epix_crypt::is_valid_address(author)
        || !epix_crypt::is_canonical_recoverable_signature(signature)
        || !epix_crypt::verify(&signed_data(record), author, signature)
    {
        return Err("Invalid local profile signature".into());
    }
    Ok(())
}

pub(super) fn verify_profile(profile: &Value, xite: &str) -> Result<(), String> {
    verify_signed(profile, xite)?;
    fields(
        profile,
        &[
            "protocol",
            "kind",
            "xite",
            "author",
            "encryption_key",
            "display_name",
            "created_at",
            "xid",
            "sign",
        ],
    )?;
    if profile["kind"] != "profile" || profile["created_at"].as_u64().is_none() {
        return Err("Invalid profile".into());
    }
    bounded_text(string(profile, "display_name")?, 80)?;
    let public = string(profile, "encryption_key")?;
    let bytes = hex::decode(public).map_err(|_| "Invalid profile encryption key")?;
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return Err("Invalid profile encryption key".into());
    }
    // This validates the curve point too, without creating or retaining a private key.
    epix_crypt::pubkey_to_address(&bytes)?;
    if !profile["xid"].is_null() {
        verify_link(&profile["xid"], profile, xite)?;
    }
    Ok(())
}

fn verify_link(link: &Value, profile: &Value, xite: &str) -> Result<(), String> {
    verify_signed(link, xite)?;
    fields(
        link,
        &[
            "protocol",
            "kind",
            "xite",
            "author",
            "name",
            "profile_author",
            "encryption_key",
            "sign",
        ],
    )?;
    if link["kind"] != "xid-link"
        || link["profile_author"] != profile["author"]
        || link["encryption_key"] != profile["encryption_key"]
    {
        return Err("Invalid xID profile binding".into());
    }
    let name = string(link, "name")?;
    if name.len() > 128
        || !name.ends_with(".epix")
        || !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
    {
        return Err("Invalid xID name".into());
    }
    Ok(())
}

pub(super) fn verify_public(record: &Value, xite: &str) -> Result<(), String> {
    verify_signed(record, xite)?;
    fields(
        record,
        &[
            "protocol", "kind", "xite", "author", "id", "sent_at", "room", "text", "profile",
            "sign",
        ],
    )?;
    if record["kind"] != "public" {
        return Err("Not a public message".into());
    }
    message_id(record)?;
    bounded_text(string(record, "room")?, 80)?;
    bounded_text(string(record, "text")?, MAX_TEXT)?;
    verify_profile(&record["profile"], xite)?;
    if record["profile"]["author"] != record["author"] {
        return Err("Author profile mismatch".into());
    }
    Ok(())
}

pub(super) fn verify_envelope(record: &Value, xite: &str) -> Result<(), String> {
    verify_signed(record, xite)?;
    fields(
        record,
        &[
            "protocol", "kind", "xite", "author", "id", "sent_at", "boxes", "sign",
        ],
    )?;
    if record["kind"] != "private" {
        return Err("Not a private envelope".into());
    }
    message_id(record)?;
    let boxes = record["boxes"].as_array().ok_or("Missing ciphertexts")?;
    if boxes.is_empty() || boxes.len() > MAX_MEMBERS {
        return Err("Invalid recipient count".into());
    }
    for ciphertext in boxes {
        let encoded = ciphertext.as_str().ok_or("Invalid ciphertext")?;
        if encoded.len() > MAX_BOX.div_ceil(3) * 4 {
            return Err("Ciphertext exceeds limit".into());
        }
        let bytes = STANDARD.decode(encoded).map_err(|_| "Invalid ciphertext")?;
        if bytes.len() > MAX_BOX || bytes.len() < 128 {
            return Err("Invalid ciphertext length".into());
        }
    }
    Ok(())
}

pub(super) fn verify_group<'a>(group: &'a Value, xite: &str) -> Result<&'a Vec<Value>, String> {
    verify_signed(group, xite)?;
    fields(
        group,
        &[
            "protocol", "kind", "xite", "author", "nonce", "title", "members", "sign",
        ],
    )?;
    if group["kind"] != "group" {
        return Err("Invalid group".into());
    }
    bounded_text(string(group, "title")?, 120)?;
    check_id(string(group, "nonce")?)?;
    let members = group["members"].as_array().ok_or("Missing members")?;
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return Err("Invalid group size".into());
    }
    let mut seen = HashSet::new();
    let mut previous = "";
    for profile in members {
        verify_profile(profile, xite)?;
        let author = string(profile, "author")?;
        if !seen.insert(author) || author <= previous {
            return Err("Group members must be unique and sorted".into());
        }
        previous = author;
    }
    if !seen.contains(string(group, "author")?) {
        return Err("Group creator is not a member".into());
    }
    Ok(members)
}

fn require_member(members: &[Value], author: &str, public: &str) -> Result<(), String> {
    if members
        .iter()
        .any(|p| p["author"] == author && p["encryption_key"] == public)
    {
        Ok(())
    } else {
        Err("Not a group member".into())
    }
}

pub(super) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key].as_str().ok_or_else(|| format!("Missing {key}"))
}
pub(super) fn bounded_text(text: &str, limit: usize) -> Result<(), String> {
    if text.trim().is_empty()
        || text.len() > limit
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        Err("Invalid text length or characters".into())
    } else {
        Ok(())
    }
}
fn fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("Expected object")?;
    if object.len() != allowed.len() || object.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err("Invalid record fields".into())
    } else {
        Ok(())
    }
}
fn check_id(id: &str) -> Result<(), String> {
    if id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("Invalid message ID".into())
    }
}
fn message_id(record: &Value) -> Result<(), String> {
    check_id(string(record, "id")?)?;
    record["sent_at"].as_u64().ok_or("Invalid timestamp")?;
    Ok(())
}
fn random_id() -> Result<String, String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| "Random source unavailable")?;
    Ok(hex::encode(bytes))
}
