/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use argh::FromArgs;
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

#[tokio::main(flavor = "current_thread")]
#[snafu::report]
async fn main() -> Result<(), sybil::Error> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    if std::env::var(sybil::PRIVSEP).is_ok() {
        return sybil::do_privilege_separation().await;
    }

    let main_args: Arguments = argh::from_env();

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
    };
    Ok(())
}
