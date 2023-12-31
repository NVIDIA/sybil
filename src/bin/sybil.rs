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
}

#[derive(FromArgs)]
#[argh(subcommand, name = "kinit")]
/// Obtains and caches an initial ticket-granting ticket for principal through protocol transition.
struct KinitArguments {
    /// principal to impersonate
    #[argh(positional)]
    principal: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
#[snafu::report]
async fn main() -> Result<(), sybil::Error> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    if std::env::var(sybil::ENV_PRIVSEP_USER).is_ok() {
        return sybil::serve_user_process().await;
    }

    let main_args: Arguments = argh::from_env();

    match main_args.command {
        Command::Kinit(args) => {
            let mut client = sybil::new_client(main_args.host, args.principal.as_deref()).await?;
            client.authenticate().await?;
            client.kinit().await?;
        }
    };
    Ok(())
}
