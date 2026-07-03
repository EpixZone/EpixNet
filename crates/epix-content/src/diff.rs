//! Line-based file diffs for publish updates (EpixNet's `util/Diff.py`). When a
//! site update changes a data file, the publisher can send a compact diff of
//! that file instead of the whole thing; the receiver patches its old copy to
//! get the new bytes without downloading. A diff that can't be applied cleanly
//! just falls back to a normal file download, so this is a bandwidth
//! optimization, never a correctness dependency.
//!
//! Wire form (msgpack, inside an `update`'s `diffs` map, `inner_path -> actions`):
//! - `["=", n]`  copy `n` bytes from the old file
//! - `["-", n]`  skip `n` bytes of the old file
//! - `["+", [line, …]]`  insert these lines (strings)

use serde_json::Value;

/// One diff action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffAction {
    /// Copy this many bytes from the old file.
    Equal(usize),
    /// Skip (delete) this many bytes of the old file.
    Remove(usize),
    /// Insert these lines (kept as byte strings).
    Insert(Vec<Vec<u8>>),
}

impl DiffAction {
    /// As a wire value (`["=", n]` / `["-", n]` / `["+", [lines]]`).
    pub fn to_value(&self) -> Value {
        match self {
            DiffAction::Equal(n) => Value::Array(vec!["=".into(), (*n).into()]),
            DiffAction::Remove(n) => Value::Array(vec!["-".into(), (*n).into()]),
            DiffAction::Insert(lines) => {
                let arr =
                    lines.iter().map(|l| Value::from(String::from_utf8_lossy(l).into_owned())).collect();
                Value::Array(vec!["+".into(), Value::Array(arr)])
            }
        }
    }

    /// Parse a wire action value.
    pub fn from_value(v: &Value) -> Option<Self> {
        let arr = v.as_array()?;
        let tag = arr.first()?.as_str()?;
        match tag {
            "=" => Some(DiffAction::Equal(arr.get(1)?.as_u64()? as usize)),
            "-" => Some(DiffAction::Remove(arr.get(1)?.as_u64()? as usize)),
            "+" => {
                let lines = arr
                    .get(1)?
                    .as_array()?
                    .iter()
                    .map(|l| match l {
                        Value::String(s) => s.clone().into_bytes(),
                        _ => Vec::new(),
                    })
                    .collect();
                Some(DiffAction::Insert(lines))
            }
            _ => None,
        }
    }
}

/// Split into lines keeping line endings (Python's `splitlines(keepends=True)` /
/// `readlines`), so byte counts line up with the file exactly.
fn split_keepends(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            lines.push(&data[start..=i]);
            start = i + 1;
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// Compute a line diff of `old` -> `new`. Returns `None` if the produced diff's
/// inserted size would exceed `limit` bytes (the caller then sends the whole
/// file). The result reconstructs `new` from `old` via [`patch`]; it need not
/// match Python's `difflib` opcodes byte-for-byte, only be correct.
pub fn diff(old: &[u8], new: &[u8], limit: Option<usize>) -> Option<Vec<DiffAction>> {
    let old_lines = split_keepends(old);
    let new_lines = split_keepends(new);

    // Longest common subsequence of lines (files are small - O(n*m) is fine).
    let (n, m) = (old_lines.len(), new_lines.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old_lines[i] == new_lines[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut actions: Vec<DiffAction> = Vec::new();
    let mut inserted_size = 0usize;
    let (mut i, mut j) = (0, 0);
    // Emit an Equal(byte_len), coalescing consecutive equal lines.
    let push_equal = |actions: &mut Vec<DiffAction>, bytes: usize| {
        if bytes == 0 {
            return;
        }
        if let Some(DiffAction::Equal(n)) = actions.last_mut() {
            *n += bytes;
        } else {
            actions.push(DiffAction::Equal(bytes));
        }
    };
    let push_remove = |actions: &mut Vec<DiffAction>, bytes: usize| {
        if bytes == 0 {
            return;
        }
        if let Some(DiffAction::Remove(n)) = actions.last_mut() {
            *n += bytes;
        } else {
            actions.push(DiffAction::Remove(bytes));
        }
    };
    let push_insert = |actions: &mut Vec<DiffAction>, line: &[u8]| {
        if let Some(DiffAction::Insert(lines)) = actions.last_mut() {
            lines.push(line.to_vec());
        } else {
            actions.push(DiffAction::Insert(vec![line.to_vec()]));
        }
    };

    while i < n && j < m {
        if old_lines[i] == new_lines[j] {
            push_equal(&mut actions, old_lines[i].len());
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            push_remove(&mut actions, old_lines[i].len());
            i += 1;
        } else {
            push_insert(&mut actions, new_lines[j]);
            inserted_size += new_lines[j].len();
            if limit.is_some_and(|l| inserted_size > l) {
                return None;
            }
            j += 1;
        }
    }
    while i < n {
        push_remove(&mut actions, old_lines[i].len());
        i += 1;
    }
    while j < m {
        push_insert(&mut actions, new_lines[j]);
        inserted_size += new_lines[j].len();
        if limit.is_some_and(|l| inserted_size > l) {
            return None;
        }
        j += 1;
    }
    Some(actions)
}

/// Apply a diff to `old`, producing the new bytes. Errors if an action runs past
/// the end of `old` (a malformed or mismatched diff).
pub fn patch(old: &[u8], actions: &[DiffAction]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for action in actions {
        match action {
            DiffAction::Equal(n) => {
                let end = cursor.checked_add(*n).filter(|&e| e <= old.len()).ok_or("diff: equal past end")?;
                out.extend_from_slice(&old[cursor..end]);
                cursor = end;
            }
            DiffAction::Remove(n) => {
                cursor = cursor.checked_add(*n).filter(|&e| e <= old.len()).ok_or("diff: remove past end")?;
            }
            DiffAction::Insert(lines) => {
                for line in lines {
                    out.extend_from_slice(line);
                }
            }
        }
    }
    Ok(out)
}

/// Parse a wire `diffs` action list (`[["=",n], …]`) into actions. Returns None
/// if any action is malformed.
pub fn actions_from_value(v: &Value) -> Option<Vec<DiffAction>> {
    v.as_array()?.iter().map(DiffAction::from_value).collect()
}

/// Serialize actions to the wire form.
pub fn actions_to_value(actions: &[DiffAction]) -> Value {
    Value::Array(actions.iter().map(DiffAction::to_value).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(old: &[u8], new: &[u8]) {
        let actions = diff(old, new, None).expect("diff within limit");
        let patched = patch(old, &actions).expect("patch applies");
        assert_eq!(patched, new, "patch(old, diff(old,new)) == new");
        // Wire round-trip of the actions.
        let v = actions_to_value(&actions);
        let parsed = actions_from_value(&v).unwrap();
        assert_eq!(patch(old, &parsed).unwrap(), new);
    }

    #[test]
    fn diff_patch_reconstructs_new() {
        roundtrip(b"a\nb\nc\n", b"a\nB\nc\n"); // change a line
        roundtrip(b"a\nb\nc\n", b"a\nb\nc\nd\n"); // append
        roundtrip(b"a\nb\nc\n", b"a\nc\n"); // delete
        roundtrip(b"", b"hello\nworld\n"); // from empty
        roundtrip(b"hello\nworld\n", b""); // to empty
        roundtrip(b"same\nsame\n", b"same\nsame\n"); // identical
        roundtrip(b"no newline at end", b"no newline changed");
    }

    #[test]
    fn identical_files_are_all_equal() {
        let data = b"line1\nline2\nline3\n";
        let actions = diff(data, data, None).unwrap();
        assert_eq!(actions, vec![DiffAction::Equal(data.len())]);
    }

    #[test]
    fn limit_aborts_large_inserts() {
        // Inserting more than the limit of new bytes returns None.
        let old = b"x\n";
        let new = b"x\naaaaaaaaaa\nbbbbbbbbbb\n";
        assert!(diff(old, new, Some(5)).is_none());
        assert!(diff(old, new, Some(1000)).is_some());
    }

    #[test]
    fn patch_rejects_out_of_range() {
        // An Equal past the end of old is an error, not a panic.
        assert!(patch(b"short", &[DiffAction::Equal(100)]).is_err());
        assert!(patch(b"short", &[DiffAction::Remove(100)]).is_err());
    }

    #[test]
    fn applies_a_python_style_action_list() {
        // Simulate what a Python peer sends: keep 2 bytes, drop 2, add a line.
        let old = b"ab_old_tail";
        let actions = vec![
            DiffAction::Equal(2),                       // "ab"
            DiffAction::Remove(4),                       // "_old"
            DiffAction::Insert(vec![b"_new".to_vec()]),  // "_new"
            DiffAction::Equal(5),                        // "_tail"
        ];
        assert_eq!(patch(old, &actions).unwrap(), b"ab_new_tail");
    }
}
