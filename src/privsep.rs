/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::conf::config;
use crate::krb;
use crate::trace::*;
use crate::{SYBIL_ENV_HOST, SYBIL_ENV_SYSLOG, SYBIL_ENV_USER};

use futures::prelude::*;
use nix::{
    errno::Errno,
    sys::{
        prctl,
        signal::{self, Signal},
    },
    unistd::{self, Pid, Uid, User},
};
use snafu::prelude::*;
use std::{
    env,
    io::{self, Write},
    os::unix::process::ExitStatusExt,
    os::{fd::AsRawFd, fd::FromRawFd, fd::OwnedFd, unix::net::UnixStream as StdUnixStream},
    process::{ChildStdout, Stdio},
};
use tarpc::{
    client::RpcError,
    context,
    serde_transport::Transport,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    io::AsyncWrite,
    net::UnixStream,
    process::{Child, Command},
    time::{self, Duration, Instant},
};
use tokio_util::task::TaskTracker;

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
    async fn refresh_creds(lifetime: Duration);
}

#[derive(Clone)]
struct UserProcess {
    tasks: TaskTracker,
}

impl PrivSep for UserProcess {
    async fn store_creds(self, _: context::Context, creds: krb::Credentials) -> Result<(), krb::Error> {
        creds.store()
    }

    async fn refresh_creds(self, _: context::Context, lifetime: Duration) {
        self.tasks.spawn(async move {
            let halflife = |l| Instant::now() + l / 2;
            let mut timer = time::interval_at(halflife(lifetime), lifetime / 10);
            let mut ticks = 0;

            while ticks < 5 {
                timer.tick().await;
                ticks += 1;

                match crate::new_client(env::var(SYBIL_ENV_HOST).ok(), None, crate::DelegatePolicy::None)
                    .and_then(|mut c| async move {
                        c.authenticate().await?;
                        c.fetch(None).await
                    })
                    .await
                {
                    Ok(lifetime) => {
                        timer.reset_at(halflife(lifetime));
                        ticks = 0
                    }
                    Err(err) => tracing::error!(error = err.chain(), "could not refresh kerberos credentials"),
                };
            }
            tracing::error!("maximum retries exhausted, exiting");
        });
    }
}

pub fn spawn_user_process_from_name(user: &str, daemonize: bool) -> Result<(PrivSepClient, PrivSepChild), Error> {
    let user = User::from_name(user)
        .context(LookupUser)?
        .context(UserNotFound { user })?;

    spawn_user_process(&user, daemonize)
}

pub fn spawn_user_process_from_uid(uid: Uid, daemonize: bool) -> Result<(PrivSepClient, PrivSepChild), Error> {
    let user = User::from_uid(uid)
        .context(LookupUser)?
        .context(UserNotFound { user: uid.to_string() })?;

    spawn_user_process(&user, daemonize)
}

pub fn spawn_user_process(user: &User, daemonize: bool) -> Result<(PrivSepClient, PrivSepChild), Error> {
    let ppid = Pid::this();
    let env: Vec<(String, String)> = env::vars()
        .filter(|(v, _)| v == "RUST_LOG" || v == "KRB5_TRACE" || v.starts_with("SYBIL_"))
        .collect();

    tracing::debug!(user = %user.name, "spawning user process");
    let (stream, ustream) = UnixStream::pair()?;
    let stdin: OwnedFd = stream.into_std()?.into();
    let mut cmd = Command::new(&config().binary_path);
    cmd.env_clear()
        .envs(env)
        .env(SYBIL_ENV_USER, &user.name)
        .current_dir("/")
        .stdin(stdin)
        .stderr(Stdio::null())
        .uid(user.uid.into())
        .gid(user.gid.into());

    if daemonize {
        cmd.stdout(Stdio::null()).env(SYBIL_ENV_SYSLOG, "1");
    } else {
        cmd.stdout(Stdio::piped());
    }

    let proc = unsafe {
        cmd.pre_exec(move || {
            if daemonize {
                unistd::setsid()?;
            } else {
                prctl::set_pdeathsig(Signal::SIGTERM)?;
                if Pid::parent() != ppid {
                    signal::kill(Pid::this(), Signal::SIGTERM)?;
                }
            }
            close_fds::set_fds_cloexec(3, &[]);
            Ok(())
        })
    }
    .spawn()?;

    let transport = Transport::from((ustream, Bincode::default()));
    let ipc = PrivSepClient::new(Default::default(), transport).spawn();
    Ok((ipc, PrivSepChild(proc)))
}

pub struct PrivSepChild(Child);

impl PrivSepChild {
    pub async fn wait(&mut self) {
        match self.0.wait().await {
            Err(err) => tracing::warn!(error = err.chain(), "could not wait on user process"),
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

    pub fn kill(&mut self) {
        self.0
            .start_kill()
            .map_err(|err| tracing::warn!(error = err.chain(), "could not kill user process"))
            .ok();
    }

    pub fn copy_output(&mut self, mut output: impl AsyncWrite + Unpin) -> impl Future<Output = ()> {
        let stdout = self.0.stdout.take();

        async move {
            if let Some(mut stdout) = stdout {
                tokio::io::copy(&mut stdout, &mut output).await.ok();
            }
        }
    }

    pub fn copy_output_blocking(&mut self, mut output: impl Write) -> impl FnOnce() {
        let stdout = self
            .0
            .stdout
            .take()
            .and_then(|s| s.into_owned_fd().ok().map(ChildStdout::from));

        move || {
            if let Some(mut stdout) = stdout {
                io::copy(&mut stdout, &mut output).ok();
            }
        }
    }

    pub fn pid(&self) -> Option<Pid> {
        self.0.id().map(|i| Pid::from_raw(i as libc::pid_t))
    }
}

#[tracing::instrument(fields(user = env::var(SYBIL_ENV_USER).unwrap()))]
pub async fn serve_user_process() -> Result<(), Error> {
    tracing::debug!("serving user process");
    let stdin = unsafe { StdUnixStream::from_raw_fd(io::stdin().as_raw_fd()) };
    let transport = UnixStream::from_std(stdin)
        .map(|s| Transport::from((s, Bincode::default())))
        .with_context(|err| {
            tracing::error!(error = err.chain(), "could not retrieve stream from stdin");
            ServeProcess
        })?;
    let proc = UserProcess {
        tasks: TaskTracker::new(),
    };

    BaseChannel::with_defaults(transport)
        .execute(proc.clone().serve())
        .buffered(1)
        .collect::<()>()
        .await;

    proc.tasks.close();
    proc.tasks.wait().await;

    tracing::debug!("stopping user process");
    Ok(())
}
