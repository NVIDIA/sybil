/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use argh::FromArgs;
use tokio::runtime;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const MAX_CONN: usize = 254;
const NUM_WORKERS: usize = 8;

#[derive(FromArgs)]
/// Sybil server.
struct Arguments {
    /// number of worker threads
    #[argh(option, short = 'w', default = "NUM_WORKERS")]
    workers: usize,
    /// address to listen on
    #[argh(option, short = 'l')]
    listen: Option<String>,
}

async fn run(args: Arguments) -> Result<(), sybil::Error> {
    let server = sybil::new_server(args.listen, MAX_CONN).await?;
    server.run().await;
    Ok(())
}

#[snafu::report]
fn main() -> Result<(), sybil::Error> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let main_args: Arguments = argh::from_env();

    runtime::Builder::new_multi_thread()
        .worker_threads(main_args.workers)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(main_args))
}
