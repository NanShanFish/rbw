# rbw

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Maintenance

I consider `rbw` to be essentially feature-complete for me at this point. While
I still use it on a daily basis, and will continue to fix regressions as they
occur, I am unlikely to spend time implementing new features on my own. If you
would like to see new functionality in `rbw`, I am more than happy to review
and merge pull requests implementing those features.

## This fork

This is a personal fork (`NanShanFish/rbw`) based on rbw `1.15.0`. The
upstream project is maintained, but new features are not a priority there, so
the changes below are carried on this branch for daily use. They have also been
submitted upstream where applicable, but are not guaranteed to be merged.

### Changes relative to upstream

* **Clear error when the refresh token is rejected** — a revoked/expired
  refresh token previously surfaced as a cryptic
  `failed to parse JSON: missing field access_token`, hiding the real cause.
  This fork reports an actionable message telling you to run `rbw purge` and
  then `rbw login`. (upstream PR
  [doy/rbw#362](https://github.com/doy/rbw/pull/362))

* **Fix editing entries with an individual encryption key** — `rbw edit` used
  to corrupt entries that carry a `key` field (item key): the edited fields
  were re-encrypted with the wrong key while the stale item key was kept, so no
  client could decrypt the entry anymore. Editing now encrypts with the item
  key and preserves the `key` field. (upstream issue
  [doy/rbw#364](https://github.com/doy/rbw/issues/364), PR
  [doy/rbw#366](https://github.com/doy/rbw/pull/366))

* **`rbw edit --field`** — edit a single field (username, name, notes,
  password, totp, uris, or a custom field) instead of only password + notes,
  mirroring `rbw get --field`. URIs are edited one per line and existing URI
  match types are preserved. (upstream issue
  [doy/rbw#365](https://github.com/doy/rbw/issues/365), PR
  [doy/rbw#367](https://github.com/doy/rbw/pull/367)). Custom field edits use
  decrypted names, prefer exact matches, and reject ambiguous matches.
  `--create` adds a missing field as a hidden custom field. Piped values keep
  lines beginning with `#` and trim only one trailing newline. (fork PR
  [#1](https://github.com/NanShanFish/rbw/pull/1))

* **SSH signing confirmation through GUI pinentry** — every signature requires
  an explicit confirmation by default. An unlocked Vault does not require the
  master password again, unless the item's own re-prompt policy requires it.
  SSH prompts use a dedicated GUI pinentry, including Windows pinentry on WSL,
  and never reuse a terminal. Cached public keys can be listed while locked.
  See [SSH Agent](#ssh-agent) for setup and configuration.

* **`rbw-dbcheck`** — a small diagnostic tool that unlocks your local vault and
  reports which entries fail to decrypt, to detect vault corruption.

### Installation / deployment

#### Build from source

The SSH confirmation features described below are on the `dev` branch. Build
that branch to use them:

```sh
git clone --branch dev git@github.com:NanShanFish/rbw.git
cd rbw
cargo build --release --locked
```

#### Install the binaries

For a per-user installation:

```sh
install -d "$HOME/.local/bin"
install -m755 target/release/rbw target/release/rbw-agent "$HOME/.local/bin/"
install -m755 target/release/rbw-dbcheck "$HOME/.local/bin/"  # optional
export PATH="$HOME/.local/bin:$PATH"
```

Keep `~/.local/bin` in your shell's `PATH` so both the CLI and agent use this
build. A system-wide installation can use `/usr/local/bin` instead (with the
appropriate permissions).

The `rbw` CLI and `rbw-agent` must be built and installed together. After an
upgrade, configure the SSH GUI pinentry as described below, then run
`rbw stop-agent` and `rbw-agent` to start the new build. An already running
agent continues using its old executable and startup configuration until it
is restarted.

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory for
  before requiring the password to be entered again. Defaults to `3600` (one
  hour).
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.
* `ssh_agent_confirmation`: Controls authorization for SSH agent signatures.
  Defaults to `always`, which shows a dedicated GUI confirmation dialog for
  every signature request. This confirmation does not ask for the master
  password; database unlock and item-level password re-prompts still apply.
  Set it to `never` to disable this additional per-signature confirmation.
* `ssh_agent_pinentry`: Optional path or command name for the GUI pinentry used
  only by SSH-agent requests. The agent probes an explicitly configured program
  at startup and rejects terminal-only implementations. With
  `ssh_agent_confirmation=always`, an unset value makes the agent search `PATH`
  for a supported GUI pinentry and refuse to start if none is usable. The
  ordinary `pinentry` setting remains in effect for normal rbw commands.

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries (but will
not attempt to log in to the server), `rbw sync` will automatically run `rbw
login` to log in to the server before downloading the password database (but
will not unlock the database), and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw stop-agent`.

`rbw help` can be used to get more information about the available
functionality.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag will show the output as JSON. In addition to matching against the name,
you can pass a UUID as the name to search for the entry with that id, or a
URL to search for an entry with a matching website entry.

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).

### SSH Agent

`rbw-agent` signs SSH authentication requests using Bitwarden **SSH Key**
items. Ed25519 and RSA keys are supported; keys stored only in secure notes
or login custom fields are not offered as SSH identities. There is no need
to export the private key or import it with `ssh-add`.

#### Configure a GUI pinentry

The default `ssh_agent_confirmation=always` requires a usable GUI pinentry
before the agent can start. On Linux, install a GUI frontend with its runtime
dependencies, then configure its executable. For example:

```sh
rbw config set ssh_agent_pinentry /usr/bin/pinentry-gnome3
rbw config set ssh_agent_confirmation always
```

`pinentry-qt` is another option. The GUI must be able to access the desktop
session in which the agent runs. Merely having a binary on disk is not enough
if its shared libraries or graphical session are unavailable.

On WSL, a Windows GUI pinentry can be invoked through WSL interoperability;
this does not require a Linux GTK/Qt installation. For a Scoop installation,
for example (adjust the path to your installation):

```sh
rbw config set ssh_agent_pinentry /mnt/d/SoftWare/Scoop/shims/pinentry.exe
rbw config set ssh_agent_confirmation always
```

Windows pinentry's CRLF Assuan responses are supported. The ordinary `pinentry`
setting is independent: it continues to control normal commands such as
`rbw unlock`, and can still point to a terminal frontend.

If `ssh_agent_pinentry` is unset, `always` searches `PATH` in this order:
`pinentry-gnome3`, `pinentry-qt`, `pinentry-qt5`, `pinentry-gui`, `pinentry-gtk`,
`pinentry-w32`, `pinentry-gtk-2`, `pinentry-mac`, and `pinentry-fltk`. Startup
checks the version output for a GUI implementation and performs a bounded,
non-interactive Assuan handshake. It refuses to start if the explicitly
configured executable fails these checks or no automatic candidate works.
An invalid explicit path is not replaced by another candidate. The handshake
does not open a dialog; runtime access to the desktop must still work.

SSH requests never fall back to `pinentry-curses`, `pinentry-tty`, or a
previous terminal. They pass no TTY and remove inherited `GPG_TTY` and `TTY`,
avoiding competition with foreground programs for password input.

#### Start the agent and select its socket

After changing the configuration or installing a new build, restart the
agent. For an account that is already registered and logged in:

```sh
rbw stop-agent
rbw-agent
rbw unlock
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"
else
    export SSH_AUTH_SOCK="${TMPDIR:-/tmp}/rbw-$(id -u)/ssh-agent-socket"
fi
```

With `XDG_RUNTIME_DIR` set, the socket is
`$XDG_RUNTIME_DIR/rbw/ssh-agent-socket`. Without a runtime directory, the
fallback is `/tmp/rbw-$(id -u)/ssh-agent-socket` (or under `TMPDIR` if set).

For a profile such as `RBW_PROFILE=work`, use the same profile for configuration
and agent commands. The corresponding paths are
`$XDG_RUNTIME_DIR/rbw-work/ssh-agent-socket` or
`/tmp/rbw-work-$(id -u)/ssh-agent-socket`. Add the appropriate `SSH_AUTH_SOCK`
export to your shell startup configuration for future terminals.

#### Confirmation and configuration options

| Option | Default | Behavior |
| --- | --- | --- |
| `ssh_agent_confirmation` | `always` | Show a GUI Allow/Cancel dialog for each signature. `never` disables this additional confirmation. |
| `ssh_agent_pinentry` | Unset | Dedicated GUI executable path or command name for SSH requests. In `always`, an unset value enables GUI discovery. In `never`, an unset value disables SSH-triggered password dialogs. An explicit value is checked at startup in either mode. |
| `pinentry` | `pinentry` | Frontend for ordinary rbw commands, including manual `rbw unlock`. Independent of the SSH GUI setting. |
| `lock_timeout` | `3600` seconds | How long the agent retains unlocked Vault keys. After locking, private-key access requires the master password again. |

With `always`, the dialog shows the requested key fingerprint and the direct
socket peer's process name and PID when available:

```text
SSH signature request

Process: ssh (pid ...)
Key: SHA256:...

Allow this signature request?
```

* **Vault unlocked:** confirm the signature without entering the master password.
* **Vault locked:** confirm, then enter the master password once to unlock the
  Vault. Later signatures need only confirmation until the Vault locks again.
* **Cancel or timeout:** the signature fails with `agent refused operation`.
* **Item-level master-password re-prompt:** this still applies independently;
  clicking Allow does not satisfy an item's password requirement.

Confirmation is per signature, not per `ssh` command. A client trying several
keys may display several dialogs. The process information is advisory: Git
usually launches `ssh`, and forwarding or proxies expose the intermediary
rather than the originating application.

SSH confirmations and password prompts share one agent-wide gate. Each
pinentry transaction has a two-minute budget, including waiting for that gate;
timeout terminates its pinentry child. An explicit `rbw lock` invalidates
in-flight authorizations.

To disable per-signature confirmation for automation:

```sh
rbw config set ssh_agent_confirmation never
rbw stop-agent
rbw-agent
```

This allows signatures without approval while the Vault is unlocked. With no
`ssh_agent_pinentry` configured, SSH access to a locked Vault fails instead of
opening a terminal prompt; unlock manually with `rbw unlock` first. An item's
master-password re-prompt still requires a configured SSH GUI pinentry. A
headless setup can therefore use `never` with manual unlocking, provided its
SSH items do not require re-prompts. To remove the GUI setting or restore
confirmation defaults:

```sh
rbw config unset ssh_agent_pinentry
rbw config unset ssh_agent_confirmation  # restores always; requires a usable GUI
```

Restart the agent after these changes.

#### Public-key cache and verification

After the first unlock, rbw stores a profile- and account-specific cache of
normalized public keys without comments, with file mode `0600`. Run
`rbw unlock` once after upgrading to create it. Unlock and sync while unlocked
refresh the cache; `rbw lock` preserves it and `rbw purge` removes it. A sync
while locked can leave stale identities until the next unlock. Signing still
checks the current encrypted Vault: removed keys fail, and new keys appear
after refreshing the cache.

Verify that listing works while locked without showing pinentry:

```sh
rbw lock
ssh-add -L
rbw unlocked  # expected to report that the agent is locked
```

Then connect to a host that accepts one of those keys:

```sh
ssh -o ControlMaster=no -o ControlPath=none user@your-host
```

With `always`, the first signature should show a confirmation and, if still
locked, an unlock prompt. A subsequent connection while unlocked should show
only confirmation, subject to item-level re-prompt policy. Reusing an existing
SSH connection does not perform a new signature and does not show a dialog.
Use `ssh -vvv` to distinguish identity listing, server acceptance of a key,
and a real agent signature request.

If the agent refuses to start, check `rbw config show`, the configured path,
the GUI runtime dependencies, and the desktop environment available to the
agent. Closing the terminal that originally launched it should not affect
Windows GUI pinentry; Linux GUI frontends still need their desktop session.


### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
