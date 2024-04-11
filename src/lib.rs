/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

mod auth;
mod conf;
mod dns;
mod gss;
mod krb;
mod privsep;
mod trace;

use crate::conf::CONFIG;
use crate::gss::{CredUsage, SecurityContext, MECH};
pub use crate::privsep::PRIVSEP;

use futures::{join, prelude::*};
use nix::errno::Errno;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{
    fmt::Display,
    io,
    net::IpAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    thread,
};
use tarpc::{
    client::RpcError,
    context::{self, Context},
    serde_transport::tcp,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{net::ToSocketAddrs, sync::Mutex};
use tracing::Instrument;

const SYBIL_PORT: u16 = 57811;
const SYBIL_SERVICE: &str = "sybil";
const SYBIL_SRV_RECORD: &str = "_sybil._tcp";
const SYBIL_CREDS_STORE: &str = "KCM:";

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
    #[snafu(display("Error while retrieving delegated credentials"))]
    GssDelegate,
    #[snafu(display("Error while generating kerberos credentials"))]
    KerberosCreds,
    #[snafu(display("Error while handling credentials storage"))]
    CredsStore,
}

#[tarpc::service]
trait Sybil {
    async fn gss_init(token: gss::Token) -> Result<Option<gss::Token>, SybilError>;
    async fn new_creds() -> Result<gss::Token, SybilError>;
    async fn put_creds() -> Result<(), SybilError>;
}

#[derive(Clone)]
struct SybilServer {
    peer: IpAddr,
    gss: Arc<Mutex<gss::ServerCtx>>,
}

pub struct Server<S: Future> {
    rpc: S,
}

pub struct Client {
    rpc: SybilClient,
    gss: gss::ClientCtx,
}

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

    async fn new_creds(self, _: Context) -> Result<gss::Token, SybilError> {
        let id = &self.authorize(auth::Permissions::KINIT).await?;

        let user = id.username().ok_or_else(|| {
            tracing::warn!("request refused due to missing user");
            SybilError::Unauthorized
        })?;
        let realm = krb::default_realm().map_err(|error| {
            tracing::error!(%error, "could not retrieve default realm");
            SybilError::KerberosCreds
        })?;

        let target_user = krb::local_user(user).map_err(|error| {
            tracing::error!(%error, principal = %format!("{user}@{realm}"), "could not retrieve local user for principal");
            SybilError::KerberosCreds
        })?;
        if user != &target_user {
            tracing::error!(%user, %realm, "translation mismatch for user principal in realm");
            return Err(SybilError::KerberosCreds);
        }

        let princ = if CONFIG.ticket.cross_realm {
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

        tracing::info!(%user, krbtgt = %princ, "new credentials request");

        tracing::debug!("forging kerberos credentials");
        let creds = krb::forge_credentials(
            user,
            &princ,
            &CONFIG.ticket.cipher,
            &CONFIG.ticket.flags,
            None,
            Some(&CONFIG.ticket.lifetime),
            Some(&CONFIG.ticket.renew_lifetime),
        )
        .map_err(|error| {
            tracing::error!(%error, %user, "could not forge credentials");
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

    async fn put_creds(self, _: Context) -> Result<(), SybilError> {
        let id = &self.authorize(auth::Permissions::WRITE).await?;

        let user = id.username().ok_or_else(|| {
            tracing::warn!("request refused due to missing user");
            SybilError::Unauthorized
        })?;

        tracing::info!(%user, principal = %id.principal, "put credentials request");

        tracing::debug!("retrieving delegated credentials");
        let gss = self.gss.lock().await;
        let creds = gss.delegated_cred().ok_or_else(|| {
            tracing::error!("delegated credentials not found in GSS context");
            SybilError::GssDelegate
        })?;

        let (uid, gid) = id.user.as_ref().map(|u| (u.uid, u.gid)).unwrap();
        tracing::debug!(ccache = %format!("{SYBIL_CREDS_STORE}{uid}"), "storing delegated credentials");

        thread::scope(|s| {
            let t = s.spawn(|| {
                Errno::result(unsafe { libc::syscall(libc::SYS_setgid, gid) })
                    .map_err(|err| format!("setgid {gid} failed: {err}"))?;
                Errno::result(unsafe { libc::syscall(libc::SYS_setuid, uid) })
                    .map_err(|err| format!("setuid {uid} failed: {err}"))?;
                creds
                    .store(SYBIL_CREDS_STORE, true, false, CredUsage::Initiate, Some(MECH))
                    .boxed()
            });
            t.join().unwrap().map_err(|error| {
                tracing::error!(%error, "could not store credentials");
                SybilError::CredsStore
            })
        })
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

pub async fn new_server(
    addrs: Option<impl ToSocketAddrs + Display>,
    max_conn: usize,
) -> Result<Server<impl Future>, Error> {
    conf::load_config_server();

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
            let peer = match c.transport().peer_addr() {
                Ok(addr) => addr.ip(),
                Err(error) => {
                    tracing::error!(%error, "could not retrieve peer address");
                    return;
                }
            };

            let span = tracing::info_span!("sybil_service", %peer);
            let srv = {
                let _enter = span.enter();
                match gss::new_server_ctx(SYBIL_SERVICE) {
                    Ok(gss) => SybilServer {
                        peer,
                        gss: Arc::new(Mutex::new(gss)),
                    },
                    Err(error) => {
                        tracing::error!(%error, "could not initialize GSS context");
                        return;
                    }
                }
            };
            c.execute(srv.serve())
                .for_each(|r| {
                    tokio::spawn(r.instrument(span.clone()))
                        .unwrap_or_else(|error| tracing::error!(%error, "could not execute task to completion"))
                })
                .await;
        })
        .buffer_unordered(max_conn)
        .collect::<()>();

    Ok(Server { rpc })
}

pub async fn new_client(
    addrs: Option<impl ToSocketAddrs + Display>,
    princ: Option<&str>,
    enterprise: bool,
    delegate: bool,
) -> Result<Client, Error> {
    conf::load_config_client();

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
    let gss = gss::new_client_ctx(princ, &format!("{SYBIL_SERVICE}@{host}"), enterprise, delegate)?;

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
        let (ipc, mut proc) = privsep::spawn_user_process(&user)?;
        let req = async {
            let res = ipc.store_creds(context::current(), creds).await;
            drop(ipc);
            res
        };
        let (resp, _) = join!(req, proc.wait());

        Ok(resp.context(privsep::IpcRequest)??)
    }

    #[tracing::instrument(skip_all)]
    pub async fn store(&mut self) -> Result<(), Error> {
        tracing::info!("sending kerberos credentials");
        self.rpc.put_creds(context::current()).await??;

        Ok(())
    }
}

pub async fn do_privilege_separation() -> Result<(), Error> {
    privsep::serve_user_process().map_err(Into::into).await
}
