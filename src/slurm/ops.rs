/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::trace::*;

use std::{cell::Cell, result::Result};
use tracing_subscriber::fmt::MakeWriter;

thread_local! {
    static REFRESH_PROCESS: Cell<Option<crate::PrivSepChild>> = const { Cell::new(None) };
}

pub async fn store_credentials(min_tkt_lifetime: Option<&str>) -> Result<(), crate::Error> {
    if min_tkt_lifetime.is_some_and(|v| !v.is_empty() && v != "0") {
        let ccache = crate::krb::default_ccache()?;
        let _ = crate::krb::Credentials::fetch(&ccache, min_tkt_lifetime, false)?;
    }

    let mut client = crate::new_client(None::<String>, None, crate::DelegatePolicy::ForceDelegate).await?;
    client.authenticate().await?;
    client.store().await?;
    Ok(())
}

pub async fn fetch_credentials(uid: u32) -> Result<(), crate::Error> {
    let mut client = crate::new_client(None::<String>, None, crate::DelegatePolicy::None).await?;
    client.authenticate().await?;

    let mut proc = client
        .fetch_and_refresh(uid.into(), crate::RefreshStrategy::Detach)
        .await?;

    if let Some(ref mut proc) = proc {
        tokio::task::spawn_blocking(proc.copy_output_blocking(crate::slurm::SpankLogger.make_writer()));
    }

    REFRESH_PROCESS.set(proc);
    Ok(())
}

pub async fn terminate() {
    if let Some(mut proc) = REFRESH_PROCESS.take() {
        proc.kill();
        proc.wait().await;
    }
}
