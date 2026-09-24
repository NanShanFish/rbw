use crate::prelude::*;

use anyhow::Context as _;

use std::io::{Read as _, Write as _};

use tokio::io::{
    AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _,
};

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
)]
#[serde(rename_all = "lowercase")]
pub enum SshAgentConfirmation {
    #[default]
    Always,
    Never,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    #[serde(default)]
    pub ssh_agent_confirmation: SshAgentConfirmation,
    #[serde(default)]
    pub ssh_agent_pinentry: Option<String>,
    pub client_cert_path: Option<std::path::PathBuf>,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            ssh_agent_confirmation: SshAgentConfirmation::default(),
            ssh_agent_pinentry: None,
            client_cert_path: None,
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

const SSH_AGENT_PINENTRY_CANDIDATES: &[&str] = &[
    "pinentry-gnome3",
    "pinentry-qt",
    "pinentry-qt5",
    "pinentry-gui",
    "pinentry-gtk",
    "pinentry-w32",
    "pinentry-gtk-2",
    "pinentry-mac",
    "pinentry-fltk",
];
const GUI_PINENTRY_MARKERS: &[&str] =
    &["gnome", "gtk", "qt", "w32", "mac", "fltk", "efl"];

async fn probe_gui_pinentry(pinentry: &str) -> anyhow::Result<()> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::process::Command::new(pinentry)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("pinentry version check timed out")?
    .with_context(|| format!("failed to start pinentry '{pinentry}'"))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "pinentry version check failed: {}",
            error.trim()
        ));
    }
    let version = String::from_utf8_lossy(&output.stdout).to_lowercase();
    if !GUI_PINENTRY_MARKERS
        .iter()
        .any(|marker| version.contains(marker))
    {
        return Err(anyhow::anyhow!(
            "pinentry did not identify itself as a GUI implementation"
        ));
    }

    let mut child = tokio::process::Command::new(pinentry)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start pinentry '{pinentry}'"))?;
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stdout.read_line(&mut line),
    )
    .await
    .context("pinentry greeting timed out")??;
    if bytes == 0 || !line.trim_end_matches(['\r', '\n']).starts_with("OK") {
        return Err(anyhow::anyhow!(
            "pinentry did not return an Assuan greeting"
        ));
    }
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"BYE\n").await?;
    drop(stdin);
    let status =
        tokio::time::timeout(std::time::Duration::from_secs(2), child.wait())
            .await
            .context("pinentry shutdown timed out")??;
    if !status.success() {
        return Err(anyhow::anyhow!("pinentry exited with {status}"));
    }
    Ok(())
}

pub async fn resolve_ssh_agent_pinentry(
    config: &Config,
) -> anyhow::Result<Option<String>> {
    if let Some(pinentry) = &config.ssh_agent_pinentry {
        probe_gui_pinentry(pinentry).await.map_err(|e| {
            anyhow::anyhow!(
                "configured ssh_agent_pinentry '{pinentry}' is unusable: {e:#}"
            )
        })?;
        return Ok(Some(pinentry.clone()));
    }
    if config.ssh_agent_confirmation == SshAgentConfirmation::Never {
        return Ok(None);
    }

    let mut errors = Vec::new();
    for candidate in SSH_AGENT_PINENTRY_CANDIDATES {
        match probe_gui_pinentry(candidate).await {
            Ok(()) => return Ok(Some((*candidate).to_string())),
            Err(e) => errors.push(format!("{candidate}: {e}")),
        }
    }
    Err(anyhow::anyhow!(
        "ssh_agent_confirmation=always requires a usable GUI pinentry; configure ssh_agent_pinentry or install one of {}\n{}",
        SSH_AGENT_PINENTRY_CANDIDATES.join(", "),
        errors.join("\n")
    ))
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut fh = std::fs::File::create(&file).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.clone(),
            }
        })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_agent_confirmation_defaults_to_always() {
        let config: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(
            config.ssh_agent_confirmation,
            SshAgentConfirmation::Always
        );
    }

    #[test]
    fn ssh_agent_confirmation_deserializes_never() {
        let config: Config =
            serde_json::from_str(r#"{"ssh_agent_confirmation":"never"}"#)
                .unwrap();
        assert_eq!(
            config.ssh_agent_confirmation,
            SshAgentConfirmation::Never
        );
        assert_eq!(config.ssh_agent_pinentry, None);
    }

    fn fake_pinentry(version: &str) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinentry-test");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  echo '{version}'\n  exit 0\nfi\nprintf 'OK hello\\r\\n'\nwhile IFS= read -r line; do\n  if [ \"$line\" = BYE ]; then\n    printf 'OK closing\\r\\n'\n    exit 0\n  fi\ndone\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        (dir, path.to_string_lossy().into_owned())
    }

    #[tokio::test]
    async fn explicit_gui_pinentry_is_probed() {
        let (_dir, path) = fake_pinentry("pinentry-w32 (pinentry) test");
        let config = Config {
            ssh_agent_pinentry: Some(path.clone()),
            ..Config::default()
        };

        assert_eq!(
            resolve_ssh_agent_pinentry(&config).await.unwrap(),
            Some(path)
        );
    }

    #[tokio::test]
    async fn terminal_pinentry_is_rejected() {
        let (_dir, path) = fake_pinentry("pinentry-curses (pinentry) test");
        let config = Config {
            ssh_agent_pinentry: Some(path),
            ..Config::default()
        };

        let error = resolve_ssh_agent_pinentry(&config)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("did not identify itself as a GUI"));
    }

    #[tokio::test]
    async fn never_without_pinentry_does_not_require_gui() {
        let config = Config {
            ssh_agent_confirmation: SshAgentConfirmation::Never,
            ..Config::default()
        };

        assert_eq!(resolve_ssh_agent_pinentry(&config).await.unwrap(), None);
    }
}
