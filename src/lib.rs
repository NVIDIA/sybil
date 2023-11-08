/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

mod dns;
mod gss;
mod krb;
use gss::SecurityContext;

use futures::{join, prelude::*};
use netaddr2::{Contains, NetAddr};
use nix::{
    errno::Errno,
    fcntl::{self, FlockArg},
    unistd,
};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{
    env,
    ffi::CString,
    fmt::Display,
    fs, io,
    net::IpAddr,
    ops::Deref,
    os::{
        fd::AsRawFd,
        fd::FromRawFd,
        unix::{net::UnixStream as StdUnixStream, process::ExitStatusExt},
    },
    path::Path,
    process::Stdio,
    sync::Arc,
};
use tarpc::{
    client::RpcError,
    context::{self, Context},
    serde_transport::{tcp, Transport},
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    net::{ToSocketAddrs, UnixStream},
    process::{Child, Command},
    sync::Mutex,
};
use tracing::Instrument;

pub const ENV_PRIVSEP_USER: &str = "SYBIL_PRIVSEP_USER";

const SYBIL_PORT: u16 = 57811;
const SYBIL_SERVICE: &str = "sybil";
const SYBIL_SRV_RECORD: &str = "_sybil._tcp";
const DEFAULT_TKT_CIPHER: &str = "aes256-sha1";
const DEFAULT_TKT_FLAGS: &str = "FRI";
const DEFAULT_TKT_LIFE: &str = "10h";
const DEFAULT_TKT_RENEW_LIFE: &str = "7d";

lazy_static::lazy_static! {
    static ref SETTINGS: Settings = config::Config::builder()
        .add_source(
            config::File::with_name(
                &option_env!("PREFIX").map_or("/".as_ref(), Path::new).join("etc/sybil").to_string_lossy(),
            )
            .required(false),
        )
        .add_source(
            config::Environment::with_prefix("SYBIL").try_parsing(true).list_separator(","),
        )
        .build()
        .and_then(config::Config::try_deserialize)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "could not load configuration");
            Settings::default()
        });
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("DNS lookup error"), context(false))]
    DnsLookup { source: dns::Error },
    #[snafu(display("RPC transport error"), context(false))]
    RpcTransport { source: io::Error },
    #[snafu(display("RPC request error"), context(false))]
    RpcRequest { source: RpcError },
    #[snafu(display("GSS context error"), context(false))]
    GssContext { source: gss::Error },
    #[snafu(display("Kerberos credentials error"), context(false))]
    KerberosCreds { source: krb::Error },
    #[snafu(display("Sybil server error"), context(false))]
    SybilServer { source: SybilError },
    #[snafu(display("Privilege separation error"), context(false))]
    PrivSep { source: PrivSepError },
}

#[derive(Deserialize)]
struct Settings {
    tkt_cipher: String,
    tkt_flags: String,
    tkt_life: String,
    tkt_renew_life: String,
    allow_networks: Vec<NetAddr>,
    allow_realms: Vec<String>,
    allow_groups: Vec<String>,
    strip_domain: bool,
    cross_realm: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tkt_cipher: DEFAULT_TKT_CIPHER.to_owned(),
            tkt_flags: DEFAULT_TKT_FLAGS.to_owned(),
            tkt_life: DEFAULT_TKT_LIFE.to_owned(),
            tkt_renew_life: DEFAULT_TKT_RENEW_LIFE.to_owned(),
            allow_networks: Default::default(),
            allow_realms: Default::default(),
            allow_groups: Default::default(),
            strip_domain: Default::default(),
            cross_realm: Default::default(),
        }
    }
}

#[derive(Debug, Snafu, Serialize, Deserialize)]
pub enum SybilError {
    #[snafu(display("Unauthorized request"))]
    Unauthorized,
    #[snafu(display("Authentication required"))]
    AuthRequired,
    #[snafu(display("Error while establishing GSS context"))]
    GssHandshake,
    #[snafu(display("Error while encrypting communication"))]
    GssEncrypt,
    #[snafu(display("Error while generating kerberos credentials"))]
    KerberosCreds,
}

#[tarpc::service]
trait Sybil {
    async fn gss_init(token: gss::Token) -> Result<Option<gss::Token>, SybilError>;
    async fn get_tgt() -> Result<gss::Token, SybilError>;
}

#[derive(Clone)]
struct SybilServer {
    client: IpAddr,
    gss: Arc<Mutex<gss::ServerCtx>>,
}

pub struct Server<S: Future> {
    rpc: S,
}

pub struct Client {
    rpc: SybilClient,
    gss: gss::ClientCtx,
}

#[tarpc::server]
impl Sybil for SybilServer {
    async fn gss_init(self, _: Context, token: gss::Token) -> Result<Option<gss::Token>, SybilError> {
        tracing::debug!("performing GSS negotiation step");
        let tok = self
            .gss
            .lock()
            .await
            .step(&token)
            .map_err(|error| {
                tracing::error!(%error, "could not initialize GSS context");
                SybilError::GssHandshake
            })?
            .map(Into::into);

        Ok(tok)
    }

    async fn get_tgt(self, _: Context) -> Result<gss::Token, SybilError> {
        let user = self.authorize().await?;

        let user = SETTINGS
            .strip_domain
            .then(|| {
                SETTINGS
                    .allow_realms
                    .iter()
                    .map(|r| r.to_lowercase())
                    .find_map(|r| user.strip_suffix(&format!("@{r}")))
            })
            .flatten()
            .unwrap_or(&user);

        let realm = krb::default_realm().map_err(|error| {
            tracing::error!(%error, "could not retrieve default realm");
            SybilError::KerberosCreds
        })?;
        let princ = if SETTINGS.cross_realm.trim().is_empty() {
            format!("{}/{realm}", krb::TGS_NAME)
        } else {
            format!("{}/{realm}@{}", krb::TGS_NAME, SETTINGS.cross_realm)
        };

        tracing::debug!(user, "forging kerberos credentials");
        let creds = krb::forge_credentials(
            user,
            &princ,
            &SETTINGS.tkt_cipher,
            &SETTINGS.tkt_flags,
            None,
            Some(&SETTINGS.tkt_life),
            Some(&SETTINGS.tkt_renew_life),
        )
        .map_err(|error| {
            tracing::error!(%error, user, "could not forge credentials");
            SybilError::KerberosCreds
        })?;

        tracing::debug!("encrypting kerberos credentials");
        self.gss
            .lock()
            .await
            .wrap(true, &creds)
            .map_err(|error| {
                tracing::error!(%error, "could not encrypt credentials");
                SybilError::GssEncrypt
            })
            .map(Into::into)
    }
}

impl SybilServer {
    async fn authorize(&self) -> Result<String, SybilError> {
        tracing::debug!("performing authorization checks");

        SETTINGS
            .allow_networks
            .iter()
            .find(|n| n.contains(&self.client))
            .ok_or_else(|| {
                tracing::warn!(client = %self.client, "request refused due to network policy");
                SybilError::Unauthorized
            })?;

        let mut gss = self.gss.lock().await;
        if !gss.is_complete() || !gss.open().unwrap_or(false) {
            tracing::warn!("request refused due to missing authentication");
            return Err(SybilError::AuthRequired);
        }

        let princ = gss::source_principal(&mut *gss).map_err(|error| {
            tracing::error!(%error, "could not retrieve source principal");
            SybilError::Unauthorized
        })?;
        SETTINGS
            .allow_realms
            .iter()
            .find(|r| princ.ends_with(&format!("@{r}")))
            .ok_or_else(|| {
                tracing::warn!(%princ, "request refused due to realm policy");
                SybilError::Unauthorized
            })?;

        let user = gss::source_username(&mut *gss).map_err(|error| {
            tracing::error!(%error, "could not retrieve source username");
            SybilError::Unauthorized
        })?;
        let groups: Vec<_> = unistd::User::from_name(&user)
            .map_err(|error| {
                tracing::error!(%error, user, "could not lookup user");
                SybilError::Unauthorized
            })?
            .ok_or_else(|| {
                tracing::warn!(user, "request refused due to user not found");
                SybilError::Unauthorized
            })
            .and_then(|u| {
                unistd::getgrouplist(&CString::new(u.name).unwrap(), u.gid).map_err(|error| {
                    tracing::error!(%error, user, "could not lookup groups");
                    SybilError::Unauthorized
                })
            })?
            .into_iter()
            .filter_map(|i| unistd::Group::from_gid(i).ok().flatten().map(|g| g.name))
            .collect();
        SETTINGS
            .allow_groups
            .iter()
            .find(|g| groups.contains(g))
            .ok_or_else(|| {
                tracing::warn!(user, ?groups, "request refused due to group policy");
                SybilError::Unauthorized
            })?;

        Ok(user)
    }
}

pub async fn new_server(
    addrs: Option<impl ToSocketAddrs + Display>,
    max_conn: usize,
) -> Result<Server<impl Future>, Error> {
    tracing::info!(
        config.tkt_cipher = ?SETTINGS.tkt_cipher,
        config.tkt_flags = ?SETTINGS.tkt_flags,
        config.tkt_life = ?SETTINGS.tkt_life,
        config.tkt_renew_life = ?SETTINGS.tkt_renew_life,
        config.allow_networks = ?SETTINGS.allow_networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        config.allow_realms = ?SETTINGS.allow_realms,
        config.allow_groups = ?SETTINGS.allow_groups,
        config.strip_domain = ?SETTINGS.strip_domain,
        config.cross_realm = ?SETTINGS.cross_realm,
        "loaded configuration"
    );
    let transport = match addrs {
        Some(addrs) => {
            tracing::info!(%addrs, "starting sybil server");
            tcp::listen(addrs, Bincode::default).await?
        }
        None => {
            let addrs = format!("0.0.0.0:{SYBIL_PORT}");
            tracing::info!(addrs, "starting sybil server");
            tcp::listen(addrs, Bincode::default).await?
        }
    };

    let rpc = transport
        .filter_map(|t| async {
            t.map_or_else(
                |error| {
                    tracing::error!(%error, "could not accept connection");
                    None
                },
                Some,
            )
        })
        .map(BaseChannel::with_defaults)
        .map(|c| async {
            let client = match c.transport().peer_addr() {
                Ok(addr) => addr.ip(),
                Err(error) => {
                    tracing::error!(%error, "could not retrieve client address");
                    return;
                }
            };

            let span = tracing::info_span!("sybil_service", %client);
            let srv = {
                let _enter = span.enter();
                match gss::new_server_ctx(SYBIL_SERVICE) {
                    Ok(gss) => SybilServer {
                        client,
                        gss: Arc::new(Mutex::new(gss)),
                    },
                    Err(error) => {
                        tracing::error!(%error, "could not initialize GSS context");
                        return;
                    }
                }
            };
            c.execute(srv.serve()).instrument(span).await;
        })
        .buffer_unordered(max_conn)
        .collect::<()>();

    Ok(Server { rpc })
}

pub async fn new_client(addrs: Option<impl ToSocketAddrs + Display>, princ: Option<&str>) -> Result<Client, Error> {
    let transport = match addrs {
        Some(addrs) => {
            tracing::info!(%addrs, "connecting to sybil server");
            tcp::connect(addrs, Bincode::default).await?
        }
        None => {
            let addrs = dns::lookup_service(SYBIL_SRV_RECORD).await?;
            tracing::info!(?addrs, "connecting to sybil server");
            tcp::connect(&*addrs, Bincode::default).await?
        }
    };

    let host = dns::lookup_address(&transport.peer_addr()?.ip()).await?;
    let rpc = SybilClient::new(Default::default(), transport).spawn();
    let gss = gss::new_client_ctx(princ, &format!("{SYBIL_SERVICE}@{host}"))?;

    Ok(Client { rpc, gss })
}

impl<S: Future> Server<S> {
    pub async fn run(self) {
        self.rpc.await;
    }
}

impl Client {
    #[tracing::instrument(skip_all)]
    pub async fn authenticate(&mut self) -> Result<(), Error> {
        let mut token: Option<gss::Token> = None;

        tracing::info!("attempting to authenticate");
        loop {
            tracing::debug!("performing GSS negotiation step");
            match self
                .gss
                .step(token.as_deref(), None)
                .map_err(Into::<gss::Error>::into)?
                .map(Into::into)
            {
                Some(tok) => match self.rpc.gss_init(context::current(), tok).await?? {
                    tok @ Some(_) => token = tok,
                    None => break,
                },
                None => break,
            };
        }

        match self.gss.info() {
            Ok(info) if info.open => {
                tracing::info!(source = %info.source_name, target = %info.target_name, "authentication succeeded")
            }
            _ => tracing::warn!("authentication done but unverified"),
        }
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn kinit(&mut self) -> Result<(), Error> {
        tracing::info!("retrieving kerberos credentials");
        let creds = self.rpc.get_tgt(context::current()).await??;

        tracing::info!("decrypting kerberos credentials");
        let creds: krb::Credentials = self
            .gss
            .unwrap(&creds)
            .map_err(Into::<gss::Error>::into)?
            .deref()
            .try_into()?;
        let user = creds.local_user()?;

        tracing::info!("storing kerberos credentials");
        let (ipc, mut proc) = spawn_user_process(&user)?;
        let req = async {
            let res = ipc.store_creds(context::current(), creds).await;
            drop(ipc);
            res
        };
        let (req, proc) = join!(req, proc.wait());

        match proc {
            Err(error) => tracing::warn!(%error, "could not wait on user process"),
            Ok(status) if !status.success() && status.code().is_some() => tracing::warn!(
                status = status.code().unwrap(),
                "user process terminated with non-zero status"
            ),
            Ok(status) if !status.success() && status.code().is_none() => tracing::warn!(
                signal = status.signal().unwrap(),
                "user process terminated with a signal"
            ),
            _ => (),
        };
        Ok(req.context(IpcRequest)??)
    }
}

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum PrivSepError {
    #[snafu(display("Failed to lookup user"))]
    LookupUser {
        #[snafu(source(from(Errno, Into::into)))]
        source: io::Error,
    },
    #[snafu(display("Failed to find user `{user}`"))]
    UserNotFound { user: String },
    #[snafu(display("Failed to issue IPC request"))]
    IpcRequest { source: RpcError },
    #[snafu(display("Failed to spawn user process"), context(false))]
    SpawnProcess { source: io::Error },
    #[snafu(display("Failed to serve user process"))]
    ServeProcess { source: io::Error },
}

#[tarpc::service]
trait PrivSep {
    async fn store_creds(creds: krb::Credentials) -> Result<(), krb::Error>;
}

#[derive(Clone)]
struct UserProcess;

#[tarpc::server]
impl PrivSep for UserProcess {
    async fn store_creds(self, _: context::Context, creds: krb::Credentials) -> Result<(), krb::Error> {
        tracing::debug!("acquiring credentials cache lock");

        let dir = env::var_os("XDG_RUNTIME_DIR")
            .and_then(|d| fs::canonicalize(d).ok())
            .unwrap_or(env::temp_dir());
        let path = dir.join(format!("sybil.{}.lock", unistd::geteuid()));

        let lock = fs::File::create(&path).map_err(|error| {
            tracing::error!(%error, path = %path.display(), "could not create lock file");
            krb::ErrorKind::CredCacheIO
        })?;
        fcntl::flock(lock.as_raw_fd(), FlockArg::LockExclusive).map_err(|error| {
            tracing::error!(%error, path = %path.display(), "could not acquire lock file");
            krb::ErrorKind::CredCacheIO
        })?;

        tracing::debug!("storing kerberos credentials");
        let res = creds.store();

        fcntl::flock(lock.as_raw_fd(), FlockArg::Unlock)
            .map_err(|error| tracing::warn!(%error, path = %path.display(), "could not release lock file"))
            .ok();
        res
    }
}

fn spawn_user_process(user: &str) -> Result<(PrivSepClient, Child), PrivSepError> {
    let (uid, gid) = unistd::User::from_name(user)
        .context(LookupUser)?
        .context(UserNotFound { user })
        .map(|u| (u.uid, u.gid))?;
    let env: Vec<(String, String)> = env::vars().filter(|(v, _)| v == "RUST_LOG").collect();

    tracing::debug!(user, "spawning user process");
    let (stream, ustream) = UnixStream::pair()?;
    let stdin = unsafe { Stdio::from_raw_fd(stream.as_raw_fd()) };
    let mut cmd = Command::new(env::current_exe()?);
    cmd.env_clear()
        .envs(env)
        .env(ENV_PRIVSEP_USER, user)
        .current_dir("/")
        .stdin(stdin)
        .uid(uid.into())
        .gid(gid.into());

    let proc = unsafe {
        cmd.pre_exec(|| {
            close_fds::set_fds_cloexec(3, &[]);
            Ok(())
        })
    }
    .kill_on_drop(true)
    .spawn()?;

    let transport = Transport::from((ustream, Bincode::default()));
    let ipc = PrivSepClient::new(Default::default(), transport).spawn();
    Ok((ipc, proc))
}

#[tracing::instrument(fields(user = env::var(ENV_PRIVSEP_USER).unwrap()))]
pub async fn serve_user_process() -> Result<(), Error> {
    tracing::debug!("serving user process");
    let stdin = unsafe { StdUnixStream::from_raw_fd(io::stdin().as_raw_fd()) };
    let transport = UnixStream::from_std(stdin)
        .map(|s| Transport::from((s, Bincode::default())))
        .with_context(|error| {
            tracing::error!(%error, "could not retrieve stream from stdin");
            ServeProcess
        })?;

    BaseChannel::with_defaults(transport).execute(UserProcess.serve()).await;
    tracing::debug!("stopping user process");
    Ok(())
}
