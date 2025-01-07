/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::trace::*;

use std::{cell::Cell, error::Error, result::Result};
use tracing_subscriber::fmt::MakeWriter;

thread_local! {
    static REFRESH_PROCESS: Cell<Option<crate::PrivSepChild>> = const { Cell::new(None) };
}

pub async fn store_credentials(min_tkt_lifetime: Option<&str>) -> Result<(), Box<dyn Error>> {
    if min_tkt_lifetime.is_some_and(|v| !v.is_empty() && v != "0") {
        crate::krb::default_ccache()
            .and_then(|ccache| crate::krb::Credentials::fetch(&ccache, min_tkt_lifetime, false))
            .map_err(|err| {
                tracing::error!(
                    error = err.chain(),
                    lifetime = min_tkt_lifetime.display(),
                    "minimum ticket lifetime requirement not met"
                );
                "Kerberos credentials do not meet the required freshness policy, \
                please re-authenticate before submitting this job again"
            })?;
    }

    let mut client = crate::new_client(None::<String>, None, crate::DelegatePolicy::ForceDelegate).await?;
    client.authenticate().await?;
    client.store().await?;
    Ok(())
}

pub async fn fetch_credentials(uid: u32) -> Result<(), Box<dyn Error>> {
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
