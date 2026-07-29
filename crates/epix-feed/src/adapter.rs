//! Value -> [`Record`] conversion driven by an owner-signed feed descriptor.
//!
//! The node stores social data as signed `epix-orset-1` records (JSON
//! `Value`s). This module maps such a record onto the organizing fields
//! [`Record`] needs, using a `FeedDescriptor` the app owner declares in its
//! content.json. The conversion is PURE and additive: it reads a record and
//! the canonical bytes the caller already derived, and never mutates or
//! re-signs anything.
//!
//! Trust boundary: the caller MUST have run `verify_record` on the record
//! first (so `author` is the recovered, authorized signer) and MUST pass the
//! exact signed bytes (`dumps_sorted(record)`) as `canonical_bytes`. A record
//! that fails verification is never handed here. A record that verifies but is
//! missing a mapped field is skipped for THAT record only (`Err(Skip)`), never
//! failing the whole feed.

use serde_json::Value;

use crate::{Kind, Record};

/// Where a descriptor finds each organizing field inside a record. A `None`
/// `target` marks a top-level item (a post) whose own id is the target others
/// attach to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMap {
    pub id: String,
    pub author: String,
    pub clock: String,
    pub target: Option<String>,
}

/// Multiplier that scales a record's clock field to the MILLISECONDS the feed
/// layer partitions on (`SEGMENT_INTERVAL_MS`).
///
/// Real apps do not all store milliseconds: an EpixPost record carries a
/// `clock` that is a CRDT supersede counter and a `date_added` in SECONDS.
/// Reading seconds as milliseconds would divide every record of a ~2.7 year
/// span into the same day-interval, collapsing the whole feed into one
/// segment and making the search skip-filter useless. So a descriptor
/// declares its unit and the adapter scales here, once.
pub fn clock_scale(unit: &str) -> Option<u64> {
    match unit {
        "ms" => Some(1),
        "s" => Some(1_000),
        _ => None,
    }
}

/// How a descriptor derives the record's [`Kind`]. `default` names the
/// non-reaction, non-tombstone kind ("post" or "comment"); a reaction feed
/// also names the fields holding the reaction kind and the active flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindSpec {
    pub default: String,
    pub reaction_kind_field: Option<String>,
    pub active_field: Option<String>,
}

/// One feed's owner-signed schema: the merge-file layout plus how to read the
/// organizing fields off each record. Parsed from a content.json `"feeds"`
/// entry; see `docs/edx-feed-descriptor.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedDescriptor {
    pub name: String,
    pub record_format: String,
    /// Glob of the merge files carrying this feed (e.g. `data/users/*/posts.json`).
    pub files: String,
    /// The array key inside each container (`records_of` uses "post"; the
    /// descriptor names it so other apps can use their own key).
    pub record_key: String,
    pub map: FieldMap,
    pub kind: KindSpec,
    /// Multiplier from the record's clock field to milliseconds (see
    /// [`clock_scale`]). 1 for a millisecond clock, 1000 for seconds.
    pub clock_scale: u64,
    /// Record field whose `true` value marks a delete (default "deleted").
    pub deleted_field: String,
    /// Record field whose `true` value marks a cross-author moderation
    /// (default "moderated"). Read only for documentation parity; a delete is
    /// a tombstone regardless of who signed it (verify already authorized it).
    pub moderated_field: String,
}

impl FeedDescriptor {
    /// Parse one `"feeds"[name]` object. `common` is the optional `_common`
    /// sibling holding `deleted_field`/`moderated_field` overrides. Returns
    /// `None` if a required key is missing or mistyped, so a malformed
    /// descriptor disables its feed instead of panicking.
    pub fn parse(name: &str, obj: &Value, common: Option<&Value>) -> Option<Self> {
        let map_obj = obj.get("map")?;
        let target = match map_obj.get("target") {
            // Explicit JSON null means top-level; a string names the field.
            Some(Value::Null) | None => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let map = FieldMap {
            id: map_obj.get("id")?.as_str()?.to_string(),
            author: map_obj.get("author")?.as_str()?.to_string(),
            clock: map_obj.get("clock")?.as_str()?.to_string(),
            target,
        };
        let kind_obj = obj.get("kind")?;
        let kind = KindSpec {
            default: kind_obj.get("default")?.as_str()?.to_string(),
            reaction_kind_field: kind_obj
                .get("reaction_kind_field")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            active_field: kind_obj
                .get("active_field")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        let common_field = |key: &str, default: &str| -> String {
            common
                .and_then(|c| c.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };
        Some(Self {
            name: name.to_string(),
            record_format: obj
                .get("record_format")
                .and_then(|v| v.as_str())
                .unwrap_or(crate::adapter::DEFAULT_RECORD_FORMAT)
                .to_string(),
            files: obj.get("files")?.as_str()?.to_string(),
            record_key: obj.get("record_key")?.as_str()?.to_string(),
            // Absent means milliseconds; an UNRECOGNISED unit returns None so
            // a typo disables the feed instead of silently mis-scaling every
            // clock (which would land the whole feed in one wrong interval).
            clock_scale: clock_scale(
                obj.get("clock_unit").and_then(|v| v.as_str()).unwrap_or("ms"),
            )?,
            map,
            kind,
            deleted_field: common_field("deleted_field", "deleted"),
            moderated_field: common_field("moderated_field", "moderated"),
        })
    }
}

/// The merge-file record format a descriptor defaults to.
pub const DEFAULT_RECORD_FORMAT: &str = "epix-orset-1";

/// Why a single record was not converted. Every variant drops just that record
/// (the feed keeps going); none is a hard error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skip {
    /// The record is not a JSON object.
    NotObject,
    /// A mapped field is absent or the wrong type.
    MissingField(&'static str),
    /// The `clock` field is missing, non-integer, or negative.
    BadClock,
}

/// Stringify a scalar field for use as an id/target key: a string verbatim, an
/// integer as its decimal form. Anything else (bool, float, array, object)
/// yields `None` so the record is skipped rather than keyed inconsistently.
fn scalar_key(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_i64().map(|i| i.to_string()),
        _ => None,
    }
}

/// Convert one verified record into a [`Record`]. `canonical_bytes` MUST be
/// the exact signed bytes (`dumps_sorted(record)`), which the caller derives
/// after `verify_record(record) == Ok`. See the module docs for the trust
/// contract.
pub fn record_from_value(
    desc: &FeedDescriptor,
    record: &Value,
    canonical_bytes: Vec<u8>,
) -> Result<Record, Skip> {
    let obj = record.as_object().ok_or(Skip::NotObject)?;

    let id = obj
        .get(&desc.map.id)
        .and_then(scalar_key)
        .ok_or(Skip::MissingField("id"))?;
    let author = obj
        .get(&desc.map.author)
        .and_then(|v| v.as_str())
        .ok_or(Skip::MissingField("author"))?
        .to_string();
    let clock_i = obj
        .get(&desc.map.clock)
        .and_then(|v| v.as_i64())
        .ok_or(Skip::BadClock)?;
    if clock_i < 0 {
        return Err(Skip::BadClock);
    }
    // Scale to milliseconds. checked_mul, not a bare `*`: a hostile or corrupt
    // record could carry a clock near i64::MAX, and a wrapped product would
    // land it in an arbitrary interval.
    let clock = (clock_i as u64).checked_mul(desc.clock_scale).ok_or(Skip::BadClock)?;

    // A top-level item (target=null) attaches to nothing; its own id is the
    // target others reference. Otherwise read the named target field.
    let target = match &desc.map.target {
        None => String::new(),
        Some(field) => obj.get(field).and_then(scalar_key).unwrap_or_default(),
    };

    let deleted = obj.get(&desc.deleted_field).and_then(|v| v.as_bool()).unwrap_or(false);

    // Precedence: a delete is a sticky tombstone on the record's OWN id (so
    // `checkpoint::tombstoned_ids` collects it and every version of that id
    // drops out); this covers self-delete and cross-author moderation alike
    // (verify already authorized the signer). Only a live record consults the
    // reaction/default kind.
    let (kind, target) = if deleted {
        (Kind::Tombstone, id.clone())
    } else if desc.kind.default == "reaction" {
        let reaction_kind = desc
            .kind
            .reaction_kind_field
            .as_ref()
            .and_then(|f| obj.get(f))
            .and_then(|v| v.as_str())
            .ok_or(Skip::MissingField("reaction_kind"))?
            .to_string();
        let active = desc
            .kind
            .active_field
            .as_ref()
            .and_then(|f| obj.get(f))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        (Kind::Reaction { kind: reaction_kind, active }, target)
    } else if desc.kind.default == "post" {
        (Kind::Post, target)
    } else {
        (Kind::Comment, target)
    };

    Ok(Record { canonical: canonical_bytes, id, author, target, clock, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn comments_descriptor() -> FeedDescriptor {
        FeedDescriptor::parse(
            "comments",
            &json!({
                "record_format": "epix-orset-1",
                "files": "data/users/*/comments.json",
                "record_key": "comment",
                "map": { "id": "comment_id", "author": "author", "clock": "clock", "target": "post_id" },
                "kind": { "default": "comment" }
            }),
            None,
        )
        .unwrap()
    }

    fn reactions_descriptor() -> FeedDescriptor {
        FeedDescriptor::parse(
            "reactions",
            &json!({
                "files": "data/users/*/reactions.json",
                "record_key": "reaction",
                "map": { "id": "reaction_id", "author": "author", "clock": "clock", "target": "target_id" },
                "kind": { "default": "reaction", "reaction_kind_field": "emoji", "active_field": "active" }
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn maps_the_named_fields() {
        let desc = comments_descriptor();
        let rec = json!({
            "comment_id": "c1", "author": "epix1abc", "clock": 42, "post_id": "p9",
            "body": "hi", "sign": "sig",
        });
        let out = record_from_value(&desc, &rec, b"canon".to_vec()).unwrap();
        assert_eq!(out.id, "c1");
        assert_eq!(out.author, "epix1abc");
        assert_eq!(out.clock, 42);
        assert_eq!(out.target, "p9");
        assert_eq!(out.kind, Kind::Comment);
        assert_eq!(out.canonical, b"canon");
    }

    #[test]
    fn numeric_id_and_target_stringify() {
        let desc = comments_descriptor();
        let rec = json!({ "comment_id": 7, "author": "epix1abc", "clock": 1, "post_id": 900 });
        let out = record_from_value(&desc, &rec, Vec::new()).unwrap();
        assert_eq!(out.id, "7");
        assert_eq!(out.target, "900");
    }

    #[test]
    fn top_level_post_has_empty_target() {
        let desc = FeedDescriptor::parse(
            "posts",
            &json!({
                "files": "data/users/*/posts.json",
                "record_key": "post",
                "map": { "id": "post_id", "author": "author", "clock": "clock", "target": null },
                "kind": { "default": "post" }
            }),
            None,
        )
        .unwrap();
        let rec = json!({ "post_id": "p1", "author": "epix1abc", "clock": 5 });
        let out = record_from_value(&desc, &rec, Vec::new()).unwrap();
        assert_eq!(out.kind, Kind::Post);
        assert!(out.target.is_empty(), "a top-level post attaches to nothing");
    }

    #[test]
    fn deleted_becomes_a_tombstone_on_its_own_id() {
        let desc = comments_descriptor();
        let rec = json!({
            "comment_id": "c1", "author": "epix1abc", "clock": 9, "post_id": "p9",
            "deleted": true,
        });
        let out = record_from_value(&desc, &rec, Vec::new()).unwrap();
        assert_eq!(out.kind, Kind::Tombstone);
        // The tombstone's target is the victim id, so tombstoned_ids collects it.
        assert_eq!(out.target, "c1");
    }

    #[test]
    fn reaction_kind_and_active_are_read() {
        let desc = reactions_descriptor();
        let like = json!({
            "reaction_id": "r1", "author": "epix1abc", "clock": 3, "target_id": "p9",
            "emoji": "like", "active": true,
        });
        let out = record_from_value(&desc, &like, Vec::new()).unwrap();
        assert_eq!(out.kind, Kind::Reaction { kind: "like".into(), active: true });

        // active defaults to true when the field is absent.
        let no_active = json!({
            "reaction_id": "r2", "author": "epix1abc", "clock": 4, "target_id": "p9",
            "emoji": "love",
        });
        let out2 = record_from_value(&desc, &no_active, Vec::new()).unwrap();
        assert_eq!(out2.kind, Kind::Reaction { kind: "love".into(), active: true });
    }

    #[test]
    fn missing_field_skips_only_that_record() {
        let desc = comments_descriptor();
        // No author -> skip; but a good record right after still converts, so a
        // single bad record never fails the feed.
        let bad = json!({ "comment_id": "c1", "clock": 1, "post_id": "p9" });
        assert_eq!(record_from_value(&desc, &bad, Vec::new()), Err(Skip::MissingField("author")));
        let good = json!({ "comment_id": "c2", "author": "epix1abc", "clock": 1, "post_id": "p9" });
        assert!(record_from_value(&desc, &good, Vec::new()).is_ok());
    }

    #[test]
    fn negative_or_missing_clock_is_bad() {
        let desc = comments_descriptor();
        let neg = json!({ "comment_id": "c1", "author": "epix1abc", "clock": -1, "post_id": "p9" });
        assert_eq!(record_from_value(&desc, &neg, Vec::new()), Err(Skip::BadClock));
        let missing = json!({ "comment_id": "c1", "author": "epix1abc", "post_id": "p9" });
        assert_eq!(record_from_value(&desc, &missing, Vec::new()), Err(Skip::BadClock));
    }

    #[test]
    fn common_overrides_deleted_field() {
        let desc = FeedDescriptor::parse(
            "comments",
            &json!({
                "files": "f", "record_key": "comment",
                "map": { "id": "comment_id", "author": "author", "clock": "clock", "target": "post_id" },
                "kind": { "default": "comment" }
            }),
            Some(&json!({ "deleted_field": "removed" })),
        )
        .unwrap();
        assert_eq!(desc.deleted_field, "removed");
        let rec = json!({
            "comment_id": "c1", "author": "epix1abc", "clock": 9, "post_id": "p9", "removed": true,
        });
        assert_eq!(record_from_value(&desc, &rec, Vec::new()).unwrap().kind, Kind::Tombstone);
    }

    /// The EpixPost descriptor against a REAL record shape from a live hub
    /// (`data/users/<id>/posts.json`). Its `clock` is a CRDT supersede counter
    /// and `date_added` is SECONDS, so this pins the seconds-to-ms scaling that
    /// keeps day-partitioning meaningful.
    #[test]
    fn epixpost_seconds_clock_scales_to_milliseconds() {
        let feeds = json!({
            "posts": {
                "files": "data/users/*/posts.json",
                "record_key": "post",
                "clock_unit": "s",
                "map": { "id": "post_id", "author": "author",
                         "clock": "date_added", "target": null },
                "kind": { "default": "post" }
            }
        });
        let desc = FeedDescriptor::parse("posts", &feeds["posts"], None)
            .expect("the EpixPost descriptor must parse");
        assert_eq!(desc.clock_scale, 1_000, "seconds scale to ms");

        // Verbatim shape of a real post (body/meta trimmed).
        let rec = json!({
            "author": "epix1qp8ur7eqqj9ynh9ng2c5d8ng8mdtu3x763xp33",
            "body": "Hello Epix!",
            "clock": 1,
            "date_added": 1_775_058_425_i64,
            "deleted": false,
            "post_id": 1_775_058_430_i64,
            "supersedes": 0
        });
        let out = record_from_value(&desc, &rec, b"canonical".to_vec()).expect("converts");
        assert_eq!(out.clock, 1_775_058_425_000, "seconds promoted to ms");
        assert_eq!(out.id, "1775058430", "integer post_id stringifies");
        assert_eq!(out.author, "epix1qp8ur7eqqj9ynh9ng2c5d8ng8mdtu3x763xp33");
        // A top-level post attaches to nothing; the index keys it under its
        // own id (see TargetIndex::add_segment).
        assert_eq!(out.target, "", "a top-level post has no attach target");
        assert_eq!(out.kind, Kind::Post);

        // The scaled clock lands in the right DAY interval, which is the whole
        // reason the unit matters: unscaled it would divide to 20.
        const DAY_MS: u64 = 86_400_000;
        assert_eq!(out.clock / DAY_MS, 20_544);
        assert_eq!(1_775_058_425_u64 / DAY_MS, 20, "unscaled would collapse the feed");

        // An unrecognised unit disables the feed rather than mis-scaling it.
        let mut bad = feeds["posts"].clone();
        bad["clock_unit"] = json!("minutes");
        assert!(FeedDescriptor::parse("posts", &bad, None).is_none());

        // Absent clock_unit still means milliseconds (existing descriptors).
        let mut ms = feeds["posts"].clone();
        ms.as_object_mut().unwrap().remove("clock_unit");
        assert_eq!(FeedDescriptor::parse("posts", &ms, None).unwrap().clock_scale, 1);
    }
}
