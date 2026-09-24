use anyhow::Context as _;
use sha2::Digest as _;

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        'attempts: for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::login(&email, password.clone(), None, None)
                .await
            {
                Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                )) => {
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    rbw::actions::send_two_factor_email(
                                        &email,
                                        &sso_email_2fa_session_token,
                                    )
                                    .await?;
                                }
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = two_factor(
                                environment,
                                &email,
                                password.clone(),
                                provider,
                            )
                            .await?;
                            login_success(
                                state.clone(),
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                password,
                                db,
                                email,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(anyhow::anyhow!(
                        "unsupported two factor methods: {providers:?}"
                    ));
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn two_factor(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
) -> anyhow::Result<()> {
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(&db).await?;

    sync(None, state.clone()).await?;
    let db = load_db().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key = Some(keys);
            state.org_keys = Some(org_keys);
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    if let Err(e) = refresh_ssh_public_key_cache(state).await {
        eprintln!("failed to refresh SSH public key cache: {e:#}");
    }

    Ok(())
}

const PINENTRY_TRANSACTION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);

pub struct SshAuthorization {
    keys: Option<rbw::locked::Keys>,
    org_keys: Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    lock_generation: u64,
}

impl SshAuthorization {
    pub fn lock_generation(&self) -> u64 {
        self.lock_generation
    }

    fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.keys.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|keys| keys.get(id))
        })
    }

    #[cfg(test)]
    fn unconfirmed(lock_generation: u64) -> Self {
        Self {
            keys: None,
            org_keys: None,
            lock_generation,
        }
    }
}

async fn with_pinentry_transaction_timeout<T>(
    timeout: std::time::Duration,
    authorization: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(timeout, authorization)
        .await
        .context("pinentry transaction timed out")?
}

async fn verify_database_password(
    pinentry: &str,
    environment: &rbw::protocol::Environment,
    description: &str,
) -> anyhow::Result<(
    rbw::locked::Keys,
    std::collections::HashMap<String, rbw::locked::Keys>,
)> {
    let db = load_db().await?;

    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };
    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };
    let Some(protected_key) = db.protected_key else {
        return Err(anyhow::anyhow!("failed to find protected key in db"));
    };
    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let email = config_email().await?;
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            Some(format!("{} (attempt {i}/3)", err_msg.take().unwrap()))
        } else {
            None
        };
        let password = rbw::pinentry::getpin(
            pinentry,
            "Master Password",
            description,
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match rbw::actions::unlock(
            &email,
            &password,
            kdf,
            iterations,
            db.memory,
            db.parallelism,
            &protected_key,
            &protected_private_key,
            &db.protected_org_keys,
        ) {
            Ok(keys) => return Ok(keys),
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to unlock database");
                }
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to unlock database"),
        }
    }

    unreachable!()
}

async fn unlock_database_with_pinentry(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    pinentry: &str,
    environment: &rbw::protocol::Environment,
    description: &str,
) -> anyhow::Result<()> {
    let lock_generation = state.lock().await.lock_generation();
    with_pinentry_transaction_timeout(PINENTRY_TRANSACTION_TIMEOUT, async {
        let pinentry_gate = state.lock().await.pinentry_gate.clone();
        let _pinentry = pinentry_gate.lock().await;
        {
            let state = state.lock().await;
            state
                .ensure_lock_generation(lock_generation)
                .context("unlock invalidated before prompting")?;
            if !state.needs_unlock() {
                return Ok(());
            }
        }

        let (keys, org_keys) =
            verify_database_password(pinentry, environment, description)
                .await?;
        let mut state = state.lock().await;
        state
            .ensure_lock_generation(lock_generation)
            .context("unlock invalidated")?;
        state.priv_key = Some(keys);
        state.org_keys = Some(org_keys);
        Ok(())
    })
    .await
}

async fn unlock_database(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    description: &str,
) -> anyhow::Result<()> {
    let pinentry = config_pinentry().await?;
    unlock_database_with_pinentry(state, &pinentry, environment, description)
        .await
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_database(
        state,
        environment,
        &format!("Unlock the local database for '{}'", rbw::dirs::profile()),
    )
    .await
}

pub async fn authorize_ssh_sign(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    pinentry: Option<&str>,
    environment: &rbw::protocol::Environment,
    requester: &str,
    key_fingerprint: &str,
) -> anyhow::Result<SshAuthorization> {
    let lock_generation = state.lock().await.lock_generation();
    let config = rbw::config::Config::load_async().await?;
    if config.ssh_agent_confirmation
        == rbw::config::SshAgentConfirmation::Never
    {
        return Ok(SshAuthorization {
            keys: None,
            org_keys: None,
            lock_generation,
        });
    }

    let pinentry = pinentry.ok_or_else(|| {
        anyhow::anyhow!(
            "SSH signature confirmation requires a configured GUI pinentry"
        )
    })?;
    with_pinentry_transaction_timeout(
        PINENTRY_TRANSACTION_TIMEOUT,
        async {
            let pinentry_gate = state.lock().await.pinentry_gate.clone();
            let _pinentry = pinentry_gate.lock().await;
            state
                .lock()
                .await
                .ensure_lock_generation(lock_generation)
                .context("SSH authorization invalidated before prompting")?;
            let (keys, org_keys) = verify_database_password(
                pinentry,
                environment,
                &format!(
                    "SSH signature request\\n\\nProcess: {requester}\\nKey: {key_fingerprint}\\n\\nEnter your master password to authorize this request."
                ),
            )
            .await?;
            state
                .lock()
                .await
                .ensure_lock_generation(lock_generation)
                .context("SSH authorization invalidated")?;

            Ok(SshAuthorization {
                keys: Some(keys),
                org_keys: Some(org_keys),
                lock_generation,
            })
        },
    )
    .await
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state.clone(), environment).await?;

    if let Err(e) = refresh_ssh_public_key_cache(state).await {
        eprintln!("failed to refresh SSH public key cache: {e:#}");
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    state.lock().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let mut db = load_db().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find refresh token in db"));
    };
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = rbw::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    state.lock().await.set_master_password_reprompt(&entries);
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db).await?;

    if !state.lock().await.needs_unlock() {
        if let Err(e) =
            refresh_ssh_public_key_cache_from_db(state.clone(), &db).await
        {
            eprintln!("failed to refresh SSH public key cache: {e:#}");
            if let Err(remove_error) = remove_ssh_public_key_cache().await {
                eprintln!(
                    "failed to remove stale SSH public key cache: {remove_error:#}"
                );
            }
        }
    }

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

fn decrypt_cipher_with_keys(
    keys: &rbw::locked::Keys,
    cipherstring: &str,
    entry_key: Option<&str>,
) -> anyhow::Result<String> {
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };
    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    skip_master_password_reprompt: bool,
    pinentry: Option<&str>,
) -> anyhow::Result<String> {
    let (requires_reprompt, pinentry_gate, lock_generation) = {
        let mut state = state.lock().await;
        if !state.master_password_reprompt_initialized() {
            let db = load_db().await?;
            state.set_master_password_reprompt(&db.entries);
        }
        let mut sha256 = sha2::Sha256::new();
        sha256.update(cipherstring);
        let reprompt_hash: [u8; 32] = sha256.finalize().into();
        (
            !skip_master_password_reprompt
                && state.master_password_reprompt.contains(&reprompt_hash),
            state.pinentry_gate.clone(),
            state.lock_generation(),
        )
    };

    if requires_reprompt {
        with_pinentry_transaction_timeout(
            PINENTRY_TRANSACTION_TIMEOUT,
            async {
                let _pinentry = pinentry_gate.lock().await;
                state
                    .lock()
                    .await
                    .ensure_lock_generation(lock_generation)
                    .context("entry access invalidated before prompting")?;
                let pinentry = pinentry.ok_or_else(|| {
                    anyhow::anyhow!(
                        "SSH key requires a master-password re-prompt; configure ssh_agent_pinentry"
                    )
                })?;
                verify_database_password(
                    pinentry,
                    environment,
                    "Accessing this entry requires the master password",
                )
                .await
            },
        )
        .await?;
    }

    let state = state.lock().await;
    state
        .ensure_lock_generation(lock_generation)
        .context("entry access invalidated")?;
    let keys = state.key(org_id).ok_or_else(|| {
        anyhow::anyhow!("failed to find decryption keys in in-memory state")
    })?;
    decrypt_cipher_with_keys(keys, cipherstring, entry_key)
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let pinentry = config_pinentry().await?;
    let plaintext = decrypt_cipher(
        state,
        environment,
        cipherstring,
        entry_key,
        org_id,
        false,
        Some(&pinentry),
    )
    .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
    entry_key: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let keys = state.key(org_id).ok_or_else(|| {
        anyhow::anyhow!("failed to find encryption keys in in-memory state")
    })?;
    let cipherstring = encrypt_with_key(keys, entry_key, plaintext)?;

    respond_encrypt(sock, cipherstring).await?;

    Ok(())
}

fn encrypt_with_key(
    keys: &rbw::locked::Keys,
    entry_key: Option<&str>,
    plaintext: &str,
) -> anyhow::Result<String> {
    let cipher_keys;
    let keys = match entry_key {
        Some(entry_key) => {
            let key_cipherstring = rbw::cipherstring::CipherString::new(
                entry_key,
            )
            .context("failed to parse individual item encryption key")?;
            cipher_keys = rbw::locked::Keys::new(
                key_cipherstring.decrypt_locked_symmetric(keys).context(
                    "failed to decrypt individual item encryption key",
                )?,
            );
            &cipher_keys
        }
        None => keys,
    };
    rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")
    .map(|c| c.to_string())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            anyhow::anyhow!("couldn't store value to clipboard: {e}")
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    config.email.map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        Ok,
    )
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn ssh_agent_cache_account() -> anyhow::Result<(String, String)> {
    let config = rbw::config::Config::load_async().await?;
    let email = config
        .email
        .clone()
        .context("failed to find email address in config")?;
    Ok((config.server_name(), email))
}

async fn load_ssh_public_key_cache() -> anyhow::Result<Option<Vec<String>>> {
    let (server, email) = ssh_agent_cache_account().await?;
    tokio::task::spawn_blocking(move || {
        rbw::ssh_agent_cache::load(&server, &email)
    })
    .await
    .context("SSH agent cache read task failed")?
}

async fn save_ssh_public_key_cache(
    public_keys: Vec<String>,
) -> anyhow::Result<()> {
    let (server, email) = ssh_agent_cache_account().await?;
    tokio::task::spawn_blocking(move || {
        rbw::ssh_agent_cache::save(&server, &email, &public_keys)
    })
    .await
    .context("SSH agent cache write task failed")?
}

async fn remove_ssh_public_key_cache() -> anyhow::Result<()> {
    let (server, email) = ssh_agent_cache_account().await?;
    tokio::task::spawn_blocking(move || {
        rbw::ssh_agent_cache::remove(&server, &email)
    })
    .await
    .context("SSH agent cache removal task failed")?
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

fn canonical_ssh_public_key(plaintext: &str) -> anyhow::Result<String> {
    let parsed = ssh_agent_lib::ssh_key::PublicKey::from_openssh(plaintext)
        .context("failed to parse SSH public key")?;
    ssh_agent_lib::ssh_key::PublicKey::new(parsed.key_data().clone(), "")
        .to_openssh()
        .context("failed to serialize SSH public key")
}

fn decrypt_ssh_public_keys(
    state: &crate::state::State,
    db: &rbw::db::Db,
) -> anyhow::Result<Vec<String>> {
    let mut public_keys = Vec::new();
    for entry in &db.entries {
        let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        else {
            continue;
        };
        let keys = state.key(entry.org_id.as_deref()).ok_or_else(|| {
            anyhow::anyhow!("failed to find SSH public key decryption keys")
        })?;
        let plaintext =
            decrypt_cipher_with_keys(keys, encrypted, entry.key.as_deref())?;
        public_keys.push(canonical_ssh_public_key(&plaintext)?);
    }
    Ok(public_keys)
}

async fn refresh_ssh_public_key_cache_from_db(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    db: &rbw::db::Db,
) -> anyhow::Result<Vec<String>> {
    let public_keys = {
        let state = state.lock().await;
        if state.needs_unlock() {
            return Err(anyhow::anyhow!(
                "cannot refresh SSH public key cache while agent is locked"
            ));
        }
        decrypt_ssh_public_keys(&state, db)?
    };
    save_ssh_public_key_cache(public_keys.clone()).await?;
    Ok(public_keys)
}

async fn refresh_ssh_public_key_cache(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let db = load_db().await?;
    refresh_ssh_public_key_cache_from_db(state, &db).await
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    pinentry: Option<&str>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<Vec<String>> {
    match load_ssh_public_key_cache().await {
        Ok(Some(public_keys)) => return Ok(public_keys),
        Ok(None) => {}
        Err(e) => {
            eprintln!(
                "failed to load SSH public key cache, rebuilding: {e:#}"
            );
            if let Err(remove_error) = remove_ssh_public_key_cache().await {
                eprintln!(
                    "failed to remove invalid SSH public key cache: {remove_error:#}"
                );
            }
        }
    }

    let pinentry = pinentry.ok_or_else(|| {
        anyhow::anyhow!(
            "SSH public-key cache is missing; run `rbw unlock` or configure ssh_agent_pinentry"
        )
    })?;
    state.lock().await.set_timeout();
    unlock_database_with_pinentry(
        state.clone(),
        pinentry,
        environment,
        &format!("Unlock the local database for '{}'", rbw::dirs::profile()),
    )
    .await?;
    refresh_ssh_public_key_cache(state).await
}

async fn decrypt_ssh_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    authorization: &SshAuthorization,
    pinentry: Option<&str>,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(keys) = authorization.key(org_id) {
        decrypt_cipher_with_keys(keys, cipherstring, entry_key)
    } else {
        decrypt_cipher(
            state,
            environment,
            cipherstring,
            entry_key,
            org_id,
            false,
            pinentry,
        )
        .await
    }
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
    authorization: &SshAuthorization,
    pinentry: Option<&str>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    if authorization.keys.is_none() && state.lock().await.needs_unlock() {
        let pinentry = pinentry.ok_or_else(|| {
            anyhow::anyhow!(
                "Vault is locked; run `rbw unlock` or configure ssh_agent_pinentry"
            )
        })?;
        state.lock().await.set_timeout();
        unlock_database_with_pinentry(
            state.clone(),
            pinentry,
            environment,
            &format!(
                "Unlock the local database for '{}'",
                rbw::dirs::profile()
            ),
        )
        .await?;
    }

    let request_bytes = request_public_key.to_bytes();
    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_ssh_cipher(
                state.clone(),
                environment,
                authorization,
                pinentry,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_ssh_cipher(
                    state.clone(),
                    environment,
                    authorization,
                    pinentry,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;

                return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                    private_key_plaintext,
                )
                .map_err(anyhow::Error::new);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(seed: u8) -> rbw::locked::Keys {
        let mut v = rbw::locked::Vec::new();
        v.extend((0..64).map(|i| seed.wrapping_add(i)));
        rbw::locked::Keys::new(v)
    }

    #[test]
    fn encrypt_with_item_key_roundtrip() {
        let master = test_keys(1);
        let item = test_keys(100);

        // the wrapped item key as stored in the cipher's `key` field
        let mut full_key = item.enc_key().to_vec();
        full_key.extend_from_slice(item.mac_key());
        let wrapped = rbw::cipherstring::CipherString::encrypt_symmetric(
            &master, &full_key,
        )
        .unwrap()
        .to_string();

        // encrypt with the item key (the fixed path)
        let ct = encrypt_with_key(&master, Some(&wrapped), "secret").unwrap();

        // decrypting with the item key succeeds
        let plain = rbw::cipherstring::CipherString::new(&ct)
            .unwrap()
            .decrypt_symmetric(&master, Some(&item))
            .unwrap();
        assert_eq!(plain, b"secret");

        // decrypting with the master key (the old broken behaviour) fails
        assert!(rbw::cipherstring::CipherString::new(&ct)
            .unwrap()
            .decrypt_symmetric(&master, None)
            .is_err());
    }

    #[test]
    fn encrypt_without_item_key_uses_master_key() {
        let master = test_keys(2);
        let ct = encrypt_with_key(&master, None, "secret").unwrap();
        let plain = rbw::cipherstring::CipherString::new(&ct)
            .unwrap()
            .decrypt_symmetric(&master, None)
            .unwrap();
        assert_eq!(plain, b"secret");
    }

    #[test]
    fn canonical_public_key_removes_comment() {
        let with_comment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA user@example";
        assert_eq!(
            canonical_ssh_public_key(with_comment).unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[test]
    fn unconfirmed_ssh_authorization_has_no_decryption_keys() {
        let authorization = SshAuthorization::unconfirmed(7);
        assert!(authorization.key(None).is_none());
        assert_eq!(authorization.lock_generation(), 7);
    }

    #[tokio::test]
    async fn pinentry_timeout_covers_the_entire_future() {
        let result = with_pinentry_transaction_timeout(
            std::time::Duration::from_millis(10),
            async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Ok(())
            },
        )
        .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pinentry transaction timed out"));
    }

    #[test]
    fn confirmed_ssh_authorization_uses_temporary_keys() {
        let authorization = SshAuthorization {
            keys: Some(test_keys(4)),
            org_keys: Some(std::collections::HashMap::new()),
            lock_generation: 9,
        };
        let ciphertext = encrypt_with_key(
            authorization.key(None).unwrap(),
            None,
            "private key",
        )
        .unwrap();

        assert_eq!(
            decrypt_cipher_with_keys(
                authorization.key(None).unwrap(),
                &ciphertext,
                None,
            )
            .unwrap(),
            "private key"
        );
        assert_eq!(authorization.lock_generation(), 9);
    }
}
