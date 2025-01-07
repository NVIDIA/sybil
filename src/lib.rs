/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

mod auth;
mod conf;
mod dns;
mod gss;
mod krb;
mod privsep;
#[cfg(feature = "slurm")]
mod slurm;
mod trace;

pub use crate::gss::{DelegatePolicy, Principal};

use crate::conf::config;
use crate::gss::{CredUsage, SecurityContext, MECH};
use crate::trace::*;

use futures::prelude::*;
use nix::{
    errno::Errno,
    unistd::{Gid, Uid, User},
};
use privsep::PrivSepChild;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{
    error::Error as StdError,
    ffi::CStr,
    fmt::Display,
    io,
    net::IpAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::{Duration, SystemTime},
};
use stubborn_io::{ReconnectOptions, StubbornTcpStream};
#[allow(unused_imports)]
use syslog_tracing::Syslog;
use tarpc::{
    client::RpcError,
    context::{self, Context},
    serde_transport::{tcp, Transport},
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    net::ToSocketAddrs,
    signal::unix::{signal, SignalKind},
    sync::Mutex,
};
use tokio_util::task::TaskTracker;
use tracing::Instrument;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const SYBIL_PORT: u16 = 57811;
const SYBIL_SERVICE: &str = "sybil";
const SYBIL_SRV_RECORD: &str = "_sybil._tcp";
const SYBIL_CREDS_STORE: &str = "KCM:";
#[allow(dead_code)]
const SYBIL_SYSLOG_IDENT: &CStr = c"sybil";

pub const SYBIL_ENV_CONFIG: &str = "SYBIL_CONFIG";
pub const SYBIL_ENV_USER: &str = "SYBIL_USER";
pub const SYBIL_ENV_HOST: &str = "SYBIL_HOST";
pub const SYBIL_ENV_SYSLOG: &str = "SYBIL_SYSLOG";

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
    #[snafu(display("Syslog initialization error"))]
    SyslogInit,
    #[snafu(display("Privilege separation error"), context(false))]
    PrivSep { source: privsep::Error },
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
    #[snafu(display("Error while looking up delegated credentials"))]
    GssDelegate,
    #[snafu(display("Error while generating credentials"))]
    CredsGenerate,
    #[snafu(display("Error while storing credentials"))]
    CredsStore,
    #[snafu(display("Error while retrieving credentials"))]
    CredsFetch,
    #[snafu(display("Requested user not found"))]
    UserNotFound,
}

#[tarpc::service]
trait Sybil {
    async fn gss_init(token: gss::Token) -> Result<Option<gss::Token>, SybilError>;
    async fn new_creds() -> Result<gss::Token, SybilError>;
    async fn put_creds() -> Result<(), SybilError>;
    async fn get_creds(uid: Option<u32>) -> Result<gss::Token, SybilError>;
}

#[derive(Clone)]
struct SybilServer {
    peer: IpAddr,
    gss: Arc<Mutex<gss::ServerCtx>>,
}

pub struct Server<S: Future> {
    rpc: S,
    tasks: TaskTracker,
}

pub struct Client {
    rpc: SybilClient,
    gss: gss::ClientCtx,
}

#[derive(PartialEq)]
pub enum RefreshStrategy {
    Wait,
    Detach,
    Daemon,
}

fn with_privileges<T, F>(uid: Uid, gid: Gid, func: F) -> Result<T, Box<dyn StdError + Send + Sync>>
where
    F: FnOnce() -> Result<T, Box<dyn StdError + Send + Sync>>,
{
    let (old_uid, old_gid) = (Uid::current(), Gid::current());

    Errno::result(unsafe { libc::syscall(libc::SYS_setresgid, gid.as_raw(), gid.as_raw(), -1) })
        .map_err(|err| format!("setresgid {gid} failed: {err}"))?;
    Errno::result(unsafe { libc::syscall(libc::SYS_setresuid, uid.as_raw(), uid.as_raw(), -1) })
        .map_err(|err| format!("setresuid {uid} failed: {err}"))?;

    let res = func();

    Errno::result(unsafe { libc::syscall(libc::SYS_setresgid, old_gid.as_raw(), old_gid.as_raw(), -1) })
        .expect("could not restore privileges: setresgid {old_gid} failed");
    Errno::result(unsafe { libc::syscall(libc::SYS_setresuid, old_uid.as_raw(), old_uid.as_raw(), -1) })
        .expect("could not restore privileges: setresuid {old_uid} failed");
    res
}

impl Sybil for SybilServer {
    async fn gss_init(self, _: Context, token: gss::Token) -> Result<Option<gss::Token>, SybilError> {
        tracing::debug!("performing GSS negotiation step");
        let tok = self
            .gss
            .lock()
            .await
            .step(&token)
            .map_err(|err| {
                tracing::error!(error = err.chain(), "could not initialize GSS context");
                SybilError::GssHandshake
            })?
            .map(Into::into);

        Ok(tok)
    }

    async fn new_creds(self, _: Context) -> Result<gss::Token, SybilError> {
        let id = &self.authorize(auth::Permissions::KINIT).await?;

        tracing::info!(principal = %id.principal, "new credentials request");

        let user = id.username(!config().ticket.fully_qualified_user).ok_or_else(|| {
            tracing::warn!(principal = %id.principal, "could not find user for principal");
            SybilError::UserNotFound
        })?;
        let realm = krb::default_realm().map_err(|err| {
            tracing::error!(error = err.chain(), "could not retrieve default realm");
            SybilError::CredsGenerate
        })?;

        let target_user = krb::local_user(user).map_err(|err| {
            tracing::error!(error = err.chain(), principal = %format!("{user}@{realm}"), "could not find user for principal");
            SybilError::CredsGenerate
        })?;
        match (User::from_name(&target_user), id.username(false)) {
            (Ok(Some(target)), Some(username)) if target.name == username => (),
            _ => {
                tracing::error!(%user, %realm, "translation mismatch for user principal in realm");
                return Err(SybilError::CredsGenerate);
            }
        }

        let princ = if config().ticket.cross_realm {
            format!(
                "{}/{realm}@{}",
                krb::TGS_NAME,
                id.principal_realm()
                    .map(str::to_uppercase)
                    .as_deref()
                    .unwrap_or(krb::ANONYMOUS_REALMSTR)
            )
        } else {
            format!("{}/{realm}", krb::TGS_NAME)
        };

        tracing::debug!(%user, krbtgt = %princ, "forging kerberos credentials");
        let creds = krb::Credentials::forge(
            user,
            &princ,
            &config().ticket.cipher,
            &config().ticket.flags,
            None,
            Some(&config().ticket.lifetime),
            Some(&config().ticket.renewable_lifetime),
        )
        .map_err(|err| {
            tracing::error!(error = err.chain(), %user, "could not forge credentials");
            SybilError::CredsGenerate
        })?;

        tracing::debug!("encrypting kerberos credentials");
        self.gss
            .lock()
            .await
            .wrap(true, &creds)
            .map_err(|err| {
                tracing::error!(error = err.chain(), "could not encrypt credentials");
                SybilError::GssEncrypt
            })
            .map(Into::into)
    }

    async fn put_creds(self, _: Context) -> Result<(), SybilError> {
        let id = &self.authorize(auth::Permissions::WRITE).await?;

        tracing::info!(principal = %id.principal, "put credentials request");

        let (uid, gid) = id.user.as_ref().map(|u| (u.uid, u.gid)).ok_or_else(|| {
            tracing::warn!(principal = %id.principal, "could not find user for principal");
            SybilError::UserNotFound
        })?;

        tracing::debug!("retrieving delegated credentials");
        let gss = self.gss.lock().await;
        let creds = gss.delegated_cred().ok_or_else(|| {
            tracing::error!("delegated credentials not found in GSS context");
            SybilError::GssDelegate
        })?;

        // XXX: Should we enforce that the delegated credentials matches our principal?

        tracing::debug!(ccache = %format!("{SYBIL_CREDS_STORE}{uid}"), "storing delegated credentials");
        with_privileges(uid, gid, || {
            creds
                .store(SYBIL_CREDS_STORE, true, true, CredUsage::Initiate, Some(MECH))
                .boxed()
        })
        .map_err(|err| {
            tracing::error!(error = err.chain(), "could not store credentials");
            SybilError::CredsStore
        })
    }

    async fn get_creds(self, _: Context, uid: Option<u32>) -> Result<gss::Token, SybilError> {
        if uid.is_some_and(|u| Uid::from_raw(u).is_root()) {
            tracing::warn!("request refused due to masquerading as root");
            return Err(SybilError::Unauthorized);
        }
        let perms = if uid.is_some() {
            auth::Permissions::READ | auth::Permissions::MASQUERADE
        } else {
            auth::Permissions::READ
        };
        let id = &self.authorize(perms).await?;

        tracing::info!(principal = %id.principal, uid = uid.display(), "get credentials request");

        let (uid, gid) = match uid {
            Some(uid) => match User::from_uid(uid.into()) {
                Err(_) | Ok(None) => {
                    tracing::debug!(uid, "could not lookup user");
                    return Err(SybilError::UserNotFound);
                }
                Ok(Some(user)) => (user.uid, user.gid),
            },
            None => match &id.user {
                None => {
                    tracing::warn!(principal = %id.principal, "could not find user for principal");
                    return Err(SybilError::UserNotFound);
                }
                Some(user) => (user.uid, user.gid),
            },
        };

        tracing::debug!(ccache = %format!("{SYBIL_CREDS_STORE}{uid}"), "fetching kerberos credentials");
        let creds = with_privileges(uid, gid, || {
            krb::Credentials::fetch(SYBIL_CREDS_STORE, Some(&config().ticket.minimum_lifetime), true).boxed()
        })
        .map_err(|err| {
            tracing::error!(error = err.chain(), "could not fetch credentials");
            SybilError::CredsFetch
        })?;

        // XXX: Should we enforce that the fetched credentials matches our UID?

        tracing::debug!("encrypting kerberos credentials");
        self.gss
            .lock()
            .await
            .wrap(true, &creds)
            .map_err(|err| {
                tracing::error!(error = err.chain(), "could not encrypt credentials");
                SybilError::GssEncrypt
            })
            .map(Into::into)
    }
}

impl SybilServer {
    async fn authorize(&self, perms: auth::Permissions) -> Result<auth::Identity, SybilError> {
        let mut gss = self.gss.lock().await;
        if !gss.is_complete() || !gss.open().unwrap_or(false) {
            tracing::warn!("request refused due to missing authentication");
            return Err(SybilError::AuthRequired);
        }
        auth::authorize(gss.deref_mut(), &self.peer, perms).ok_or(SybilError::Unauthorized)
    }
}

fn new_service(peer: IpAddr) -> Option<(SybilServer, tracing::Span)> {
    let span = tracing::info_span!("sybil_service", %peer).entered();

    let srv = match gss::new_server_ctx(Principal::Common(SYBIL_SERVICE)) {
        Ok(gss) => SybilServer {
            peer,
            gss: Arc::new(Mutex::new(gss)),
        },
        Err(err) => {
            tracing::error!(error = err.chain(), "could not initialize GSS context");
            return None;
        }
    };
    Some((srv, span.exit()))
}

pub async fn new_server(
    addrs: Option<impl ToSocketAddrs + Display>,
    max_conn: usize,
) -> Result<Server<impl Future>, Error> {
    conf::load_server_config();

    let transport = match addrs {
        Some(addrs) => {
            tracing::info!(%addrs, "starting sybil server");
            tcp::listen(addrs, Bincode::default).await?
        }
        None => {
            let addrs = format!("0.0.0.0:{SYBIL_PORT}");
            tracing::info!(%addrs, "starting sybil server");
            tcp::listen(addrs, Bincode::default).await?
        }
    };

    let tasks = TaskTracker::new();
    let rt = tasks.clone();

    let rpc = transport
        .filter_map(|t| async {
            t.map_or_else(
                |err| {
                    tracing::error!(error = err.chain(), "could not accept connection");
                    None
                },
                Some,
            )
        })
        .map(BaseChannel::with_defaults)
        .map(move |c| {
            let rt = rt.clone();

            async move {
                let peer = match c.transport().peer_addr() {
                    Ok(addr) => addr.ip(),
                    Err(err) => {
                        tracing::error!(error = err.chain(), "could not retrieve peer address");
                        return;
                    }
                };
                let Some((srv, span)) = new_service(peer) else {
                    return;
                };

                let stream = c.execute(srv.serve());
                tokio::pin!(stream);
                while let Some(req) = stream.next().await {
                    rt.spawn(req.instrument(span.clone()));
                }
            }
        })
        .buffer_unordered(max_conn)
        .collect::<()>();

    Ok(Server { rpc, tasks })
}

pub async fn new_client(
    addrs: Option<impl ToSocketAddrs + Display + Sync + Unpin + Send + Clone + 'static>,
    princ: Option<Principal<'_>>,
    delegate: DelegatePolicy,
) -> Result<Client, Error> {
    conf::load_client_config();

    let retries = ReconnectOptions::new()
        .with_exit_if_first_connect_fails(false)
        .with_retries_generator(|| vec![Duration::from_secs(1), Duration::from_secs(5), Duration::from_secs(10)]);

    let (host, rpc) = match addrs {
        _ if !config().server_addrs.is_empty() => {
            let addrs = config().server_addrs.as_slice();
            tracing::info!(?addrs, "connecting to sybil server");
            let stream = StubbornTcpStream::connect_with_options(addrs, retries).await?;
            let host = dns::lookup_address(&stream.deref().peer_addr()?.ip()).await?;
            let transport = Transport::from((stream, Bincode::default()));
            let rpc = SybilClient::new(Default::default(), transport).spawn();
            (host, rpc)
        }
        Some(addrs) => {
            tracing::info!(%addrs, "connecting to sybil server");
            let stream = StubbornTcpStream::connect_with_options(addrs, retries).await?;
            let host = dns::lookup_address(&stream.deref().peer_addr()?.ip()).await?;
            let transport = Transport::from((stream, Bincode::default()));
            let rpc = SybilClient::new(Default::default(), transport).spawn();
            (host, rpc)
        }
        None => {
            let addrs = dns::lookup_service(SYBIL_SRV_RECORD).await?;
            tracing::info!(?addrs, "connecting to sybil server");
            let stream = StubbornTcpStream::connect_with_options(&*addrs.leak(), retries).await?; // FIXME avoid leak
            let host = dns::lookup_address(&stream.deref().peer_addr()?.ip()).await?;
            let transport = Transport::from((stream, Bincode::default()));
            let rpc = SybilClient::new(Default::default(), transport).spawn();
            (host, rpc)
        }
    };
    let gss = gss::new_client_ctx(princ, Principal::Common(&format!("{SYBIL_SERVICE}@{host}")), delegate)?;

    Ok(Client { rpc, gss })
}

impl<S: Future> Server<S> {
    pub async fn run(self) {
        let mut sigint = match signal(SignalKind::interrupt()) {
            Err(err) => {
                tracing::error!(error = err.chain(), "could not setup SIGINT handler");
                return;
            }
            Ok(sig) => sig,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Err(err) => {
                tracing::error!(error = err.chain(), "could not setup SIGTERM handler");
                return;
            }
            Ok(sig) => sig,
        };

        tokio::select! {
            _ = self.rpc => return,
            _ = sigint.recv() => (),
            _ = sigterm.recv() => (),
        };
        self.tasks.close();
        self.tasks.wait().await;
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
        let creds = self.rpc.new_creds(context::current()).await??;

        tracing::info!("decrypting kerberos credentials");
        let creds: krb::Credentials = self
            .gss
            .unwrap(&creds)
            .map_err(Into::<gss::Error>::into)?
            .deref()
            .try_into()?;
        let user = creds.local_user()?;

        tracing::info!("storing kerberos credentials");
        let (ipc, mut proc) = privsep::spawn_user_process_from_name(&user, false)?;
        let req = async {
            let resp = ipc.store_creds(context::current(), creds).await;
            drop(ipc);
            resp.context(privsep::IpcRequest)
        };
        let (resp, _, _) = tokio::join!(req, proc.copy_output(tokio::io::stdout()), proc.wait());
        resp??;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn store(&mut self) -> Result<(), Error> {
        tracing::info!("sending kerberos credentials");
        self.rpc.put_creds(context::current()).await??;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn fetch(&mut self, uid: Option<u32>) -> Result<Duration, Error> {
        tracing::info!("retrieving kerberos credentials");
        let creds = self.rpc.get_creds(context::current(), uid).await??;

        tracing::info!("decrypting kerberos credentials");
        let creds: krb::Credentials = self
            .gss
            .unwrap(&creds)
            .map_err(Into::<gss::Error>::into)?
            .deref()
            .try_into()?;
        let lifetime = creds
            .lifetime()?
            .duration_since(SystemTime::now())
            .map_err(Into::<krb::Error>::into)?;

        tracing::info!("storing kerberos credentials");
        match uid.map(Into::into) {
            Some(uid) if uid != Uid::effective() => {
                let (ipc, mut proc) = privsep::spawn_user_process_from_uid(uid, false)?;
                let req = async {
                    let resp = ipc.store_creds(context::current(), creds).await;
                    drop(ipc);
                    resp.context(privsep::IpcRequest)
                };
                let (resp, _, _) = tokio::join!(req, proc.copy_output(tokio::io::stdout()), proc.wait());
                resp??;
            }
            _ => creds.store()?,
        };

        Ok(lifetime)
    }

    #[tracing::instrument(skip_all)]
    pub async fn fetch_and_refresh(
        &mut self,
        uid: Option<u32>,
        strat: RefreshStrategy,
    ) -> Result<Option<PrivSepChild>, Error> {
        tracing::info!("retrieving kerberos credentials");
        let creds = self.rpc.get_creds(context::current(), uid).await??;

        tracing::info!("decrypting kerberos credentials");
        let creds: krb::Credentials = self
            .gss
            .unwrap(&creds)
            .map_err(Into::<gss::Error>::into)?
            .deref()
            .try_into()?;
        let lifetime = creds
            .lifetime()?
            .duration_since(SystemTime::now())
            .map_err(Into::<krb::Error>::into)?;

        tracing::info!("storing kerberos credentials");
        let (ipc, mut proc) = privsep::spawn_user_process_from_uid(
            uid.map_or_else(Uid::effective, Into::into),
            strat == RefreshStrategy::Daemon,
        )?;
        ipc.store_creds(context::current(), creds).await??;
        tracing::info!("starting refreshing kerberos credentials");
        ipc.refresh_creds(context::current(), lifetime).await?;

        match strat {
            RefreshStrategy::Detach | RefreshStrategy::Daemon => Ok(Some(proc)),
            RefreshStrategy::Wait => {
                drop(ipc);
                tokio::join!(proc.copy_output(tokio::io::stdout()), proc.wait());
                Ok(None)
            }
        }
    }
}

#[cfg(not(feature = "slurm"))]
pub fn setup_logging() -> Result<(), Error> {
    let layer = if std::env::var(SYBIL_ENV_SYSLOG).is_ok() {
        fmt::layer()
            .without_time()
            .with_level(false)
            .compact()
            .with_writer(
                Syslog::new(SYBIL_SYSLOG_IDENT, Default::default(), Default::default()).ok_or(Error::SyslogInit)?,
            )
            .boxed()
    } else if std::env::var("RUST_LOG_STYLE").is_ok_and(|v| v == "systemd" || v == "slurm") {
        fmt::layer().without_time().compact().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(layer)
        .init();

    Ok(())
}

#[cfg(feature = "slurm")]
pub fn setup_logging() -> Result<(), Error> {
    let layer = fmt::layer().without_time().compact().with_writer(slurm::SpankLogger);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(layer)
        .init();

    Ok(())
}

pub async fn do_privilege_separation() -> Result<(), Error> {
    privsep::serve_user_process().err_into().await
}
