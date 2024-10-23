/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use argh::FromArgs;
use std::ffi::CStr;
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
    /// renew credentials indefinitely
    #[argh(switch, short = 'R')]
    renew: bool,
    /// detach the renewing process
    #[argh(switch, short = 'd')]
    detach: bool,
}

#[tokio::main(flavor = "current_thread")]
#[snafu::report]
async fn main() -> Result<(), sybil::Error> {
    if std::env::var(sybil::SYBIL_ENV_SYSLOG).is_ok() {
        let syslog = Syslog::new(
            CStr::from_bytes_with_nul(b"sybil\0").unwrap(),
            Default::default(),
            Default::default(),
        )
        .unwrap();

        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(syslog))
            .with(EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    }

    if std::env::var(sybil::SYBIL_ENV_USER).is_ok() {
        return sybil::do_privilege_separation().await;
    }

    let main_args: Arguments = argh::from_env();
    if let Some(host) = &main_args.host {
        std::env::set_var(sybil::SYBIL_ENV_HOST, host);
    }

    match main_args.command {
        Command::Kinit(args) => {
            let mut client =
                sybil::new_client(main_args.host, args.principal.as_deref(), args.enterprise, false).await?;
            client.authenticate().await?;
            client.kinit().await?;
        }
        Command::Store(_) => {
            let mut client = sybil::new_client(main_args.host, None, false, true).await?;
            client.authenticate().await?;
            client.store().await?;
        }
        Command::Fetch(args) => {
            let mut client = sybil::new_client(main_args.host, None, false, false).await?;
            client.authenticate().await?;
            if args.renew {
                client.fetch_and_renew(args.uid, args.detach).await?;
            } else {
                client.fetch(args.uid).await?;
            }
        }
    };
    Ok(())
}
