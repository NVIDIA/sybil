/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use argh::FromArgs;
use syslog_tracing::Syslog;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(FromArgs)]
/// Sybil client.
struct Arguments {
    /// address of the sybil server
    #[argh(option, short = 'h')]
    host: Option<String>,
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Kinit(KinitArguments),
    Store(StoreArguments),
    Fetch(FetchArguments),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "kinit")]
/// Obtains and caches an initial ticket-granting ticket for principal through protocol transition.
struct KinitArguments {
    /// treat principal as an enterprise name
    #[argh(switch, short = 'E')]
    enterprise: bool,
    /// principal to impersonate
    #[argh(positional)]
    principal: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "store")]
/// Delegate the current credentials to the remote Sybil server for storage.
struct StoreArguments {}

#[derive(FromArgs)]
#[argh(subcommand, name = "fetch")]
/// Fetch credentials from the remote Sybil server and store them in cache.
struct FetchArguments {
    /// UID to masquerade as
    #[argh(option, short = 'u')]
    uid: Option<u32>,
    /// refresh credentials indefinitely
    #[argh(switch, short = 'R')]
    refresh: bool,
    /// daemonize the refreshing process
    #[argh(switch, short = 'd')]
    daemonize: bool,
}

fn setup_log(syslog: bool) {
    let layer = if syslog {
        let writer = Syslog::new(c"sybil", Default::default(), Default::default()).expect("could not open syslog");

        fmt::layer()
            .without_time()
            .with_level(false)
            .compact()
            .with_writer(writer)
            .boxed()
    } else if std::env::var("RUST_LOG_STYLE").is_ok_and(|v| v == "SYSTEMD") {
        fmt::layer().without_time().compact().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(layer)
        .with(EnvFilter::from_default_env())
        .init();
}

#[tokio::main(flavor = "current_thread")]
#[snafu::report]
async fn main() -> Result<(), sybil::Error> {
    setup_log(std::env::var(sybil::SYBIL_ENV_SYSLOG).is_ok());

    if std::env::var(sybil::SYBIL_ENV_USER).is_ok() {
        return sybil::do_privilege_separation().await;
    }

    let main_args: Arguments = argh::from_env();
    if let Some(host) = &main_args.host {
        std::env::set_var(sybil::SYBIL_ENV_HOST, host);
    }

    match main_args.command {
        Command::Kinit(args) => {
            let princ = if args.enterprise {
                args.principal.as_deref().map(sybil::Principal::Enterprise)
            } else {
                args.principal.as_deref().map(sybil::Principal::Common)
            };
            let mut client = sybil::new_client(main_args.host, princ, sybil::DelegatePolicy::None).await?;
            client.authenticate().await?;
            client.kinit().await?;
        }
        Command::Store(_) => {
            let mut client = sybil::new_client(main_args.host, None, sybil::DelegatePolicy::ForceDelegate).await?;
            client.authenticate().await?;
            client.store().await?;
        }
        Command::Fetch(args) => {
            let mut client = sybil::new_client(main_args.host, None, sybil::DelegatePolicy::None).await?;
            client.authenticate().await?;
            if args.refresh {
                let strat = if args.daemonize {
                    sybil::RefreshStrategy::Daemon
                } else {
                    sybil::RefreshStrategy::Wait
                };
                if let Some(pid) = client.fetch_and_refresh(args.uid, strat).await? {
                    println!("{pid}");
                }
            } else {
                client.fetch(args.uid).await?;
            }
        }
    };
    Ok(())
}
