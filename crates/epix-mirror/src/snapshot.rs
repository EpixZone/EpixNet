use crate::{
    catalog::Catalog,
    decode, encode,
    filesystem::{digest_stream, ensure_space, read_bounded, walk, Pending},
    formats, open_regular, CATALOG, MAX_BYTES, MAX_CATALOG, MAX_FILE,
};
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::Path,
};

pub struct StageOptions<'a> {
    pub source: &'a Path,
    pub output: &'a Path,
    pub manager: &'a str,
    pub expires: &'a str,
    pub url_map: Option<&'a Path>,
}

pub fn validate(root: &Path) -> Result<Catalog> {
    let bytes = read_bounded(open_regular(root, CATALOG)?, MAX_CATALOG)?;
    let catalog: Catalog = serde_json::from_value(decode(&bytes)?)?;
    catalog.check()?;
    for (relative, expected) in &catalog.files {
        let mut file = open_regular(root, &format!("repo/{relative}"))?;
        ensure!(
            digest_stream(&mut file, None)? == *expected,
            "Snapshot file changed: {relative}"
        );
    }
    formats::validate(
        &catalog.manager,
        &root.join("repo"),
        &catalog.files,
        crate::timestamp(&catalog.expires)?,
    )?;
    Ok(catalog)
}

pub fn stage(options: StageOptions<'_>) -> Result<Catalog> {
    let source = options.source.canonicalize()?;
    ensure!(source.is_dir(), "Source is not a directory");
    let output = std::path::absolute(options.output)?;
    ensure!(
        !output.starts_with(&source),
        "Output must be outside the public source directory"
    );
    let mapping = match options.url_map {
        Some(path) => {
            serde_json::from_value(decode(&read_bounded(File::open(path)?, MAX_CATALOG)?)?)?
        }
        None => BTreeMap::new(),
    };
    let pending = Pending::new(&output)?;
    ensure!(
        !pending.path().canonicalize()?.starts_with(&source),
        "Output must be outside the public source directory"
    );
    let mut files = BTreeMap::new();
    let mut total = 0;
    for relative in walk(&source)? {
        let name = relative
            .rsplit('/')
            .next()
            .context("Missing file name")?
            .to_ascii_lowercase();
        ensure!(
            !["users.json", "content.json", "privatekey", "secring.gpg"].contains(&name.as_str()),
            "Source contains identity/signing data; select only public repository files"
        );
        let mut original = open_regular(&source, &relative)?;
        let metadata = original.metadata()?;
        ensure!(
            metadata.len() <= MAX_FILE && total + metadata.len() <= MAX_BYTES,
            "Source exceeds snapshot byte limits"
        );
        ensure_space(pending.path(), metadata.len())?;
        let target = pending.path().join("repo").join(&relative);
        fs::create_dir_all(target.parent().context("Missing target parent")?)?;
        let mut writer = File::create_new(&target)?;
        let info = digest_stream(&mut original, Some(&mut writer))?;
        ensure!(
            info.size == metadata.len()
                && original.metadata()?.modified()? == metadata.modified()?,
            "Source changed while staging"
        );
        writer.sync_all()?;
        total += info.size;
        ensure!(total <= MAX_BYTES, "Snapshot exceeds 15 GiB");
        files.insert(relative, info);
    }
    let catalog = Catalog::new(
        options.manager.into(),
        options.expires.into(),
        files,
        mapping,
    )?;
    fs::write(
        pending.path().join(CATALOG),
        encode(&serde_json::to_value(&catalog)?)?,
    )?;
    validate(pending.path())?;
    pending.commit()?;
    Ok(catalog)
}
