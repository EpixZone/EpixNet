//! Durable sidebar settings and maintenance actions.

use super::*;

const MB: i64 = 1024 * 1024;

fn validate_schema(schema: &DbSchema) -> Result<(), String> {
    let db = Database::open_in_memory().map_err(|error| error.to_string())?;
    db.apply_schema(schema).map_err(|error| error.to_string())?;
    // Every map regex is compiled by update_json, even when it does not
    // match this probe. Validation never touches the currently served rows.
    db.populate_values_filtered(
        schema,
        &[("__schema_validation__.json".into(), json!({}))],
        &[],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

impl AppState {
    /// Serialize with registry writers, and expose a setting only after its
    /// durable write succeeds. A failed write leaves the previous value live.
    async fn change_sidebar_settings(
        &self,
        address: &str,
        change: impl Fn(&mut XiteSettings),
    ) -> Result<(), String> {
        let _registry = self.xite_registry_lock.lock().await;
        if self.boot_restore_pending() {
            return Err("Xites are still being restored. Try again after startup.".into());
        }
        let mut xites = self.xites.write().await;
        let target = xites
            .get(address)
            .ok_or_else(|| format!("Unknown xite: {address}"))?;
        let canonical = canonical_address(target.content.as_ref(), address);
        let previous: Vec<_> = xites
            .iter_mut()
            .filter_map(|(key, xite)| {
                if canonical_address(xite.content.as_ref(), key) != canonical {
                    return None;
                }
                let previous = xite.settings.clone();
                change(&mut xite.settings);
                Some((key.clone(), previous))
            })
            .collect();
        let saved = Self::xite_registry_bytes(&xites, &Default::default())
            .and_then(|bytes| self.write_xite_registry_bytes(&bytes));
        if let Err(error) = saved {
            for (key, settings) in previous {
                xites.get_mut(&key).unwrap().settings = settings;
            }
            return Err(format!("Could not save xite settings: {error}"));
        }
        Ok(())
    }

    /// User mutations keep the previous in-memory identity on write failure.
    /// The file writer preserves every other user's entry in users.json.
    pub(super) async fn change_sidebar_user<T>(
        &self,
        change: impl FnOnce(&mut User) -> Result<T, String>,
    ) -> Result<T, String> {
        let result = {
            let mut user = self.user.write().await;
            let mut next = user.clone();
            let result = change(&mut next)?;
            if let Some(path) = &self.user_path {
                next.save(path)
                    .map_err(|error| format!("Could not save user settings: {error}"))?;
            }
            *user = next;
            result
        };
        #[cfg(feature = "multiuser")]
        self.multiuser_sync_active_checked().await?;
        Ok(result)
    }

    #[cfg(feature = "multiuser")]
    pub(super) async fn multiuser_sync_active_checked(&self) -> Result<(), String> {
        let active = self.user.read().await.clone();
        let mut store = self.multi_users.write().await;
        let mut next = store.clone();
        next.insert(active.master_address.clone(), active);
        if let Some(path) = &self.multi_users_path {
            let bytes = serde_json::to_vec_pretty(&next).map_err(|error| error.to_string())?;
            Self::write_durable_private_file(path, &bytes)
                .map_err(|error| format!("Could not save the identity store: {error}"))?;
        }
        *store = next;
        Ok(())
    }

    pub async fn set_global_settings_checked(&self, value: Value) -> Result<(), String> {
        let Value::Object(incoming) = value else {
            return Err("User settings must be an object".into());
        };
        self.change_sidebar_user(|user| {
            user.settings.extend(incoming);
            Ok(())
        })
        .await?;
        // Broadcast the confirmed settings after persistence and user-lock
        // release so every subscribed wrapper can update its theme live.
        self.push_server_info().await;
        Ok(())
    }

    pub async fn set_owned_checked(&self, address: &str, owned: bool) -> Result<(), String> {
        self.change_sidebar_settings(address, |settings| settings.own = owned)
            .await?;
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_size_limit_checked(&self, address: &str, limit: i64) -> Result<(), String> {
        if !(1..=i64::MAX / MB).contains(&limit) {
            return Err(format!(
                "Storage limit must be a whole number between 1 and {} MB",
                i64::MAX / MB
            ));
        }
        self.change_sidebar_settings(address, |settings| settings.size_limit = Some(limit))
            .await?;
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_serving_checked(&self, address: &str, serving: bool) -> Result<(), String> {
        self.change_sidebar_settings(address, |settings| settings.serving = serving)
            .await?;
        if !serving {
            self.optional_one_shots.lock().unwrap().remove(address);
        }
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_favorite_checked(&self, address: &str, favorite: bool) -> Result<(), String> {
        self.change_sidebar_settings(address, |settings| settings.favorite = favorite)
            .await?;
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_autodownloadoptional_checked(
        self: &Arc<Self>,
        address: &str,
        on: bool,
    ) -> Result<(), String> {
        self.change_sidebar_settings(address, |settings| {
            settings.autodownloadoptional = on;
            if on {
                settings.download_optional = true;
            }
        })
        .await?;
        self.refresh_optional_owed(address).await;
        if on {
            self.spawn_optional_download(address, None);
        } else {
            self.optional_one_shots.lock().unwrap().remove(address);
            self.set_optional_progress(address, None).await;
        }
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_download_optional_checked(
        self: &Arc<Self>,
        address: &str,
        on: bool,
        trigger_download: bool,
    ) -> Result<(), String> {
        self.change_sidebar_settings(address, |settings| {
            settings.download_optional = on;
            if !on {
                settings.autodownloadoptional = false;
            }
        })
        .await?;
        if !on {
            self.optional_one_shots.lock().unwrap().remove(address);
            self.optional_prompts.lock().unwrap().remove(address);
            self.retention_consents.lock().unwrap().remove(address);
            self.set_optional_progress(address, None).await;
        } else if trigger_download {
            // On-demand alone grants no whole-xite download. The predownload
            // setting, when already enabled, may resume its existing promise.
            if self.optional_pass_should_continue(address, None).await {
                self.spawn_optional_download(address, None);
            }
        }
        self.refresh_optional_owed(address).await;
        self.push_xite_info(address).await;
        Ok(())
    }

    pub async fn set_optional_file_limit(&self, address: &str, limit: i64) -> Result<(), String> {
        if !(0..=i64::MAX / MB).contains(&limit) {
            return Err(format!(
                "Automatic file limit must be a whole number between 0 and {} MB",
                i64::MAX / MB
            ));
        }
        self.change_sidebar_settings(address, |settings| {
            settings.autodownload_bigfile_size_limit = Some(limit);
        })
        .await?;
        self.mark_optional_dirty(address);
        self.refresh_optional_owed(address).await;
        self.push_xite_info(address).await;
        Ok(())
    }

    pub(super) async fn optional_file_limit_bytes(&self, address: &str) -> Option<u64> {
        self.xites
            .read()
            .await
            .get(address)
            .and_then(|x| x.settings.autodownload_bigfile_size_limit)
            .filter(|limit| *limit > 0)
            .map(|limit| limit.saturating_mul(MB) as u64)
    }

    async fn change_siteblock(&self, address: &str, reason: Option<&str>) -> Result<(), String> {
        let mut filters = self.filters.write().await;
        let mut next = filters.clone();
        if let Some(reason) = reason {
            next["siteblocks"][address] = json!({"reason": reason, "date_added": now_secs()});
        } else if let Some(blocks) = next["siteblocks"].as_object_mut() {
            blocks.remove(address);
        }
        if let Some(path) = &self.filters_path {
            let bytes = serde_json::to_vec_pretty(&next).map_err(|error| error.to_string())?;
            Self::write_durable_private_file(path, &bytes)
                .map_err(|error| format!("Could not save blocked xites: {error}"))?;
        }
        *filters = next;
        Ok(())
    }

    pub async fn siteblock_add_checked(&self, address: &str, reason: &str) -> Result<(), String> {
        self.change_siteblock(address, Some(reason)).await
    }

    pub async fn siteblock_remove_checked(&self, address: &str) -> Result<(), String> {
        self.change_siteblock(address, None).await
    }

    /// Reload accepted schema metadata. With an unchanged table layout this
    /// keeps the current rows; a changed layout is rebuilt before replacing
    /// the live database, so an invalid schema cannot destroy its old rows.
    pub async fn reload_xite_db_schema(&self, address: &str) -> Result<(), String> {
        let _activation = self.xite_activation_gate.clone().read_owned().await;
        let canonical = {
            let xites = self.xites.read().await;
            let x = xites
                .get(address)
                .ok_or_else(|| format!("Unknown xite: {address}"))?;
            canonical_address(x.content.as_ref(), address)
        };
        let _manifest = self
            .acquire_manifest_mutex(&canonical, "content.json")
            .await?;
        let _tree = self.tree_mutation_lock(&canonical).lock_owned().await;
        // Another rebuild may have completed while this request waited for
        // the locks. Preserve its current rows, never a pre-lock connection.
        let (storage, content, own, old_schema, old_db) = {
            let xites = self.xites.read().await;
            let x = xites
                .get(address)
                .ok_or("The xite was removed during schema reload")?;
            (
                x.storage.clone(),
                x.content.clone(),
                x.settings.own,
                x.db_schema.clone(),
                x.db.clone(),
            )
        };
        let filter_epoch = self.db_filter_epoch();
        let muted = self.muted_authors().await;
        let (paths, snapshot) = self
            .rebuild_paths_and_snapshot(
                address,
                &canonical,
                &storage,
                content.as_ref(),
                own,
                false,
                None,
            )
            .await
            .ok_or("Could not verify the database schema; the current database was kept")?;
        if !paths.iter().any(|path| path == "dbschema.json") {
            return Err("This xite has no verified database schema".into());
        }
        let schema: DbSchema = if let Some(snapshot) = &snapshot {
            let value = snapshot
                .values
                .iter()
                .find(|(path, _)| path == "dbschema.json")
                .ok_or("The database schema is unavailable")?;
            serde_json::from_value(value.1.clone())
                .map_err(|error| format!("Invalid database schema: {error}"))?
        } else {
            let bytes =
                read_regular_xite_file_bounded(&storage, "dbschema.json", MAX_DB_SCHEMA_BYTES)?;
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid database schema: {error}"))?
        };
        if !epix_content::verify::is_valid_relative_path(&schema.db_file) {
            return Err("Invalid database file path in schema".into());
        }
        let same_layout = old_schema.as_ref().is_some_and(|old| {
            old.version == schema.version
                && old.db_file == schema.db_file
                && serde_json::to_value(&old.tables).ok()
                    == serde_json::to_value(&schema.tables).ok()
                && old.json_table_cols() == schema.json_table_cols()
        });
        let db = if same_layout && old_db.is_some() {
            // Validate the reloaded schema without applying destructive DDL
            // to the live connection. Mapping/feed metadata is swapped below.
            validate_schema(&schema)
                .map_err(|error| format!("Could not reload database schema: {error}"))?;
            old_db
        } else {
            Some(
                build_xite_db(
                    &storage,
                    &muted,
                    &paths,
                    snapshot.as_ref().map(|snapshot| snapshot.values.as_slice()),
                )
                .ok_or(
                    "Could not build the changed database schema; the current database was kept",
                )?
                .0,
            )
        };
        let epoch = self.verified_index_epoch(&canonical);
        {
            let mut xites = self.xites.write().await;
            let x = xites
                .get_mut(address)
                .ok_or("The xite was removed during schema reload")?;
            if x.storage.root() != storage.root()
                || x.content != content
                || self.db_filter_epoch() != filter_epoch
            {
                return Err("The xite changed during schema reload. Try again.".into());
            }
            x.db = db;
            x.db_schema = Some(schema.clone());
            x.db_verified_epoch = epoch;
            x.db_source_epoch = self.db_source_epoch(&canonical);
            x.db_merger_epoch = self.db_merger_epoch();
            x.db_filter_epoch = filter_epoch;
            x.db_generation = self.next_db_generation();
        }
        drop(_tree);
        drop(_manifest);
        drop(_activation);
        if schema.version == 3 && !self.reset_merger_index(address).await {
            return Err("Schema reloaded, but the merged database could not be refreshed".into());
        }
        Ok(())
    }

    pub async fn rebuild_xite_db_checked(&self, address: &str) -> Result<(), String> {
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or_else(|| format!("Unknown xite: {address}"))?;
        let bytes = read_regular_xite_file_bounded(&storage, "dbschema.json", MAX_DB_SCHEMA_BYTES)
            .map_err(|error| format!("Could not read database schema: {error}"))?;
        let schema: DbSchema = serde_json::from_slice(&bytes)
            .map_err(|error| format!("Invalid database schema: {error}"))?;
        if !epix_content::verify::is_valid_relative_path(&schema.db_file) {
            return Err("Invalid database file path in schema".into());
        }
        validate_schema(&schema).map_err(|error| format!("Invalid database schema: {error}"))?;
        if !self.rebuild_xite_db_reverify(address).await {
            return Err(
                "Database rebuild failed; check the node log for verification or storage errors"
                    .into(),
            );
        }
        if !self
            .xites
            .read()
            .await
            .get(address)
            .is_some_and(|x| x.db.is_some())
        {
            return Err(
                "Database rebuild produced no database; its schema or data could not be verified"
                    .into(),
            );
        }
        Ok(())
    }

    /// A deliberate, bounded pass over the currently missing optional files.
    /// This grants no standing consent and is never enrolled in retry loops.
    pub async fn download_previous_optional(
        self: &Arc<Self>,
        address: &str,
    ) -> Result<Value, String> {
        if !self.has_xite(address).await {
            return Err(format!("Unknown xite: {address}"));
        }
        if !self.is_serving(address).await {
            return Err("Resume this xite before downloading optional files".into());
        }
        let files = self.missing_optional_files(address, None).await.len();
        if files == 0 {
            return Ok(json!({"status": "complete", "files": 0}));
        }
        if self.transport.read().await.is_none() {
            return Err("The network is not running; optional files cannot be downloaded".into());
        }
        if !self
            .optional_downloads_in_flight
            .lock()
            .unwrap()
            .insert(address.to_string())
        {
            return Err("An optional download is already running for this xite".into());
        }
        self.optional_one_shots
            .lock()
            .unwrap()
            .insert(address.to_string());
        let state = self.clone();
        let address = address.to_string();
        tokio::spawn(async move {
            let (fetched, failed, cancelled) = state
                .download_optional_files_inner(&address, None, true)
                .await;
            let message = if cancelled {
                format!("Optional download stopped after {fetched} file(s).")
            } else if failed > 0 {
                format!("Downloaded {fetched} optional file(s); {failed} could not be downloaded. Use Download previous files to retry.")
            } else {
                format!("Optional download finished: {fetched} file(s) downloaded.")
            };
            state.push_notification(
                if cancelled {
                    "info"
                } else if failed > 0 {
                    "error"
                } else {
                    "done"
                },
                &message,
                10000,
            );
        });
        Ok(json!({"status": "started", "files": files}))
    }
}

#[cfg(test)]
mod tests;
