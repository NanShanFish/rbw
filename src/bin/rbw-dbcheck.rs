use anyhow::Context as _;
use std::os::unix::ffi::OsStringExt as _;

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });
    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}

fn decrypt_str(
    cs: &str,
    keys: &rbw::locked::Keys,
    entry_key: Option<&rbw::locked::Keys>,
) -> anyhow::Result<String> {
    let cs = rbw::cipherstring::CipherString::new(cs)?;
    let plain = cs
        .decrypt_symmetric(keys, entry_key)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let config = rbw::config::Config::load()?;
    let email = config
        .email
        .as_deref()
        .context("failed to find email in config")?;
    let server = config.server_name();
    let db =
        rbw::db::Db::load(&server, email).context("failed to load db")?;

    let password = rt.block_on(rbw::pinentry::getpin(
        &config.pinentry,
        "Master Password",
        "Scan vault for corrupt entries",
        None,
        &get_environment(),
        true,
    ))?;

    let kdf = db.kdf.context("failed to find kdf type in db")?;
    let iterations =
        db.iterations.context("failed to find kdf iterations")?;
    let memory = db.memory;
    let parallelism = db.parallelism;
    let protected_key = db
        .protected_key
        .as_deref()
        .context("missing protected_key")?;
    let protected_private_key = db
        .protected_private_key
        .as_deref()
        .context("missing protected_private_key")?;

    let (keys, org_keys) = rbw::actions::unlock(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
        protected_private_key,
        &db.protected_org_keys,
    )?;

    println!(
        "scanning {} entries ({} org keys available)",
        db.entries.len(),
        org_keys.len()
    );

    let mut corrupt = 0usize;
    for entry in &db.entries {
        let base = entry.org_id.as_ref().map_or_else(
            || Some((&keys, "master".to_string())),
            |org_id| {
                org_keys.get(org_id).map(|k| (k, format!("org:{org_id}")))
            },
        );
        let Some((base, key_src)) = base else {
            println!(
                "  {:?} MISSING KEY for org {:?} ({} entries corrupt?)",
                entry.id, entry.org_id, entry.name
            );
            corrupt += 1;
            continue;
        };

        let entry_key = match &entry.key {
            Some(k) => match rbw::cipherstring::CipherString::new(k)
                .and_then(|c| c.decrypt_locked_symmetric(base))
                .map(rbw::locked::Keys::new)
            {
                Ok(k) => Some(k),
                Err(e) => {
                    println!("  {}  KEY_DECRYPT_FAIL  {e}", entry.id);
                    corrupt += 1;
                    continue;
                }
            },
            None => None,
        };

        let mut problems: Vec<&str> = vec![];
        let name_ok =
            decrypt_str(&entry.name, base, entry_key.as_ref()).is_ok();
        if !name_ok {
            problems.push("name");
            println!("  {}  NAME_DECRYPT_FAIL", entry.id);
        }
        if let rbw::db::EntryData::Login { password, .. } = &entry.data {
            if password.as_ref().is_some_and(|pw| {
                decrypt_str(pw, base, entry_key.as_ref()).is_err()
            }) {
                problems.push("password");
            }
        }
        if let Some(notes) = &entry.notes {
            if decrypt_str(notes, base, entry_key.as_ref()).is_err() {
                problems.push("notes");
            }
        }
        if problems.is_empty() {
            let name =
                decrypt_str(&entry.name, base, entry_key.as_ref()).unwrap();
            println!("  {}  OK  name={name:?}", entry.id);
        } else {
            corrupt += 1;
            let name = if name_ok {
                decrypt_str(&entry.name, base, entry_key.as_ref()).unwrap()
            } else {
                String::new()
            };
            let mut username = String::new();
            let mut password = String::new();
            if let rbw::db::EntryData::Login {
                username: u,
                password: p,
                ..
            } = &entry.data
            {
                if let Some(u) = u {
                    username = decrypt_str(u, base, entry_key.as_ref())
                        .unwrap_or_default();
                }
                if let Some(p) = p {
                    password = decrypt_str(p, base, entry_key.as_ref())
                        .unwrap_or_default();
                }
            }
            println!(
                "  {}  CORRUPT (key_src={key_src}, item_key={})  parts=[{}]  name={name:?}  user={username:?}  pw={password:?}",
                entry.id,
                entry.key.is_some(),
                problems.join(","),
            );
        }
    }
    println!("done: {corrupt} corrupt entries");
    Ok(())
}
