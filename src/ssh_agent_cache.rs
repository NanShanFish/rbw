use anyhow::Context as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

const CACHE_VERSION: u8 = 1;

#[derive(serde::Deserialize, serde::Serialize)]
struct Cache {
    version: u8,
    public_keys: Vec<String>,
}

pub fn load(
    server: &str,
    email: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    load_from_path(&crate::dirs::ssh_agent_cache_file(server, email))
}

fn load_from_path(
    path: &std::path::Path,
) -> anyhow::Result<Option<Vec<String>>> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "failed to read SSH agent cache at {}",
                    path.display()
                )
            })
        }
    };
    let cache: Cache =
        serde_json::from_slice(&contents).with_context(|| {
            format!("failed to parse SSH agent cache at {}", path.display())
        })?;
    if cache.version != CACHE_VERSION {
        return Ok(None);
    }
    validate_public_keys(&cache.public_keys)?;
    Ok(Some(cache.public_keys))
}

pub fn save(
    server: &str,
    email: &str,
    public_keys: &[String],
) -> anyhow::Result<()> {
    save_to_path(
        &crate::dirs::ssh_agent_cache_file(server, email),
        public_keys,
    )
}

fn save_to_path(
    path: &std::path::Path,
    public_keys: &[String],
) -> anyhow::Result<()> {
    validate_public_keys(public_keys)?;
    let parent = path.parent().context("SSH agent cache has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create SSH agent cache directory {}",
            parent.display()
        )
    })?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| {
            format!(
                "failed to secure SSH agent cache directory {}",
                parent.display()
            )
        })?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("failed to create temporary SSH agent cache")?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("failed to secure temporary SSH agent cache")?;
    serde_json::to_writer(
        &mut temporary,
        &Cache {
            version: CACHE_VERSION,
            public_keys: public_keys.to_vec(),
        },
    )
    .context("failed to serialize SSH agent cache")?;
    temporary
        .flush()
        .context("failed to flush SSH agent cache")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync SSH agent cache")?;
    temporary
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| {
            format!("failed to replace SSH agent cache at {}", path.display())
        })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!("failed to secure SSH agent cache at {}", path.display())
        })?;
    Ok(())
}

pub fn remove(server: &str, email: &str) -> anyhow::Result<()> {
    remove_path(&crate::dirs::ssh_agent_cache_file(server, email))
}

fn remove_path(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| {
            format!("failed to remove SSH agent cache at {}", path.display())
        }),
    }
}

fn validate_public_keys(public_keys: &[String]) -> anyhow::Result<()> {
    for public_key in public_keys {
        public_key
            .parse::<ssh_agent_lib::ssh_key::PublicKey>()
            .context("SSH agent cache contains an invalid public key")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn cache_roundtrip_is_private_and_replaceable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities.json");

        save_to_path(&path, &[TEST_KEY.to_string()]).unwrap();
        assert_eq!(
            load_from_path(&path).unwrap(),
            Some(vec![TEST_KEY.to_string()])
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        save_to_path(&path, &[]).unwrap();
        assert_eq!(load_from_path(&path).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn cache_rejects_invalid_keys_and_ignores_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities.json");

        assert!(save_to_path(&path, &["not a key".to_string()]).is_err());
        std::fs::write(
            &path,
            br#"{"version":1,"public_keys":["not a key"]}"#,
        )
        .unwrap();
        assert!(load_from_path(&path).is_err());
        std::fs::write(
            &path,
            br#"{"version":2,"public_keys":["not a key"]}"#,
        )
        .unwrap();
        assert_eq!(load_from_path(&path).unwrap(), None);
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities.json");
        std::fs::write(&path, b"cache").unwrap();

        remove_path(&path).unwrap();
        remove_path(&path).unwrap();
        assert!(!path.exists());
    }
}
