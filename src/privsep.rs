/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::krb;

use futures::prelude::*;
use nix::{
    errno::Errno,
    fcntl::{self, FlockArg},
    unistd,
};
use snafu::prelude::*;
use std::{
    env, fs, io,
    os::unix::process::ExitStatusExt,
    os::{fd::AsRawFd, fd::FromRawFd, unix::net::UnixStream as StdUnixStream},
    process::Stdio,
};
use tarpc::{
    client::RpcError,
    context,
    serde_transport::Transport,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    net::UnixStream,
    process::{Child, Command},
};

pub const PRIVSEP: &str = "SYBIL_PRIVSEP_USER";

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to lookup user"))]
    LookupUser {
        #[snafu(source(from(Errno, Into::into)))]
        source: io::Error,
    },
    #[snafu(display("Failed to find user `{user}`"))]
    UserNotFound { user: String },
    #[snafu(display("Failed to issue IPC request"), visibility(pub(crate)))]
    IpcRequest { source: RpcError },
    #[snafu(display("Failed to spawn user process"), context(false))]
    SpawnProcess { source: io::Error },
    #[snafu(display("Failed to serve user process"))]
    ServeProcess { source: io::Error },
}

#[tarpc::service]
pub trait PrivSep {
    async fn store_creds(creds: krb::Credentials) -> Result<(), krb::Error>;
}

#[derive(Clone)]
struct UserProcess;

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
        let _lock = fcntl::Flock::lock(lock, FlockArg::LockExclusive).map_err(|(_, error)| {
            tracing::error!(%error, path = %path.display(), "could not acquire lock file");
            krb::ErrorKind::CredCacheIO
        })?;

        tracing::debug!("storing kerberos credentials");
        creds.store()
    }
}

pub fn spawn_user_process(user: &str) -> Result<(PrivSepClient, PrivSepChild), Error> {
    let (uid, gid) = unistd::User::from_name(user)
        .context(LookupUser)?
        .context(UserNotFound { user })
        .map(|u| (u.uid, u.gid))?;
    let env: Vec<(String, String)> = env::vars()
        .filter(|(v, _)| v == "RUST_LOG" || v == "KRB5_TRACE")
        .collect();

    tracing::debug!(%user, "spawning user process");
    let (stream, ustream) = UnixStream::pair()?;
    let stdin = unsafe { Stdio::from_raw_fd(stream.as_raw_fd()) };
    let mut cmd = Command::new(env::current_exe()?);
    cmd.env_clear()
        .envs(env)
        .env(PRIVSEP, user)
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
    Ok((ipc, PrivSepChild(proc)))
}

pub struct PrivSepChild(Child);

impl PrivSepChild {
    pub async fn wait(&mut self) {
        match self.0.wait().await {
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
    }
}

#[tracing::instrument(fields(user = env::var(PRIVSEP).unwrap()))]
pub async fn serve_user_process() -> Result<(), Error> {
    tracing::debug!("serving user process");
    let stdin = unsafe { StdUnixStream::from_raw_fd(io::stdin().as_raw_fd()) };
    let transport = UnixStream::from_std(stdin)
        .map(|s| Transport::from((s, Bincode::default())))
        .with_context(|error| {
            tracing::error!(%error, "could not retrieve stream from stdin");
            ServeProcess
        })?;

    BaseChannel::with_defaults(transport)
        .execute(UserProcess.serve())
        .for_each(|r| {
            tokio::spawn(r).unwrap_or_else(|error| tracing::error!(%error, "could not execute task to completion"))
        })
        .await;
    tracing::debug!("stopping user process");
    Ok(())
}
