/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use argh::FromArgs;
use chrono::{DateTime, Local};
use std::env;

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
    List(ListArguments),
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

#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
/// List credentials present in the remote Sybil server.
struct ListArguments {
    /// UID to masquerade as
    #[argh(option, short = 'u')]
    uids: Vec<u32>,
}

#[tokio::main(flavor = "current_thread")]
#[snafu::report]
async fn main() -> Result<(), sybil::Error> {
    sybil::setup_logging()?;

    if env::var(sybil::SYBIL_ENV_USER).is_ok() {
        return sybil::do_privilege_separation().await;
    }

    let main_args: Arguments = argh::from_env();
    if let Some(host) = &main_args.host {
        unsafe { env::set_var(sybil::SYBIL_ENV_HOST, host) };
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
                if let Some(pid) = client.fetch_and_refresh(args.uid, strat).await?.and_then(|p| p.pid()) {
                    println!("{pid}");
                }
            } else {
                client.fetch(args.uid).await?;
            }
        }
        Command::List(args) => {
            let mut client = sybil::new_client(main_args.host, None, sybil::DelegatePolicy::None).await?;
            client.authenticate().await?;
            let info = client.list(&args.uids).await?;

            println!(
                "{:<12}{:<21}{:<21}{:<21}{:<9}",
                "UID", "START_TIME", "END_TIME", "RENEW_UNTIL", "PRINCIPAL"
            );
            for i in info {
                println!(
                    "{:<12}{:<21}{:<21}{:<21}{}",
                    i.uid,
                    DateTime::<Local>::from(i.start_time).format("%Y-%m-%dT%H:%M:%S"),
                    DateTime::<Local>::from(i.end_time).format("%Y-%m-%dT%H:%M:%S"),
                    DateTime::<Local>::from(i.renew_until).format("%Y-%m-%dT%H:%M:%S"),
                    i.principal,
                );
            }
        }
    };
    Ok(())
}
