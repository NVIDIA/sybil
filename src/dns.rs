/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use rand::Rng;
use snafu::prelude::*;
use std::{
    cmp::Reverse,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};
use trust_dns_resolver::{
    error::ResolveError,
    proto::rr::{domain::Name, rdata::srv::SRV},
    AsyncResolver,
};

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to resolve address `{addr}`"))]
    ReverseLookup { addr: IpAddr, source: ResolveError },
    #[snafu(display("Failed to find host for address `{addr}`"))]
    ReverseHost { addr: IpAddr },
    #[snafu(display("Failed to resolve service `{srv}`"))]
    ServiceLookup { srv: String, source: ResolveError },
    #[snafu(display("Failed to find addresses for service `{srv}`"))]
    ServiceAddrs { srv: String },
}

pub async fn lookup_address(addr: &IpAddr) -> Result<String, Error> {
    let resolver = AsyncResolver::tokio_from_system_conf().context(ReverseLookup { addr: *addr })?;

    tracing::debug!(address = %addr, "resolving host record");
    resolver
        .reverse_lookup(*addr)
        .await
        .context(ReverseLookup { addr: *addr })?
        .into_iter()
        .next()
        .as_deref()
        .map(Name::to_utf8)
        .ok_or(Error::ReverseHost { addr: *addr })
}

pub async fn lookup_service(srv: &str) -> Result<Vec<SocketAddr>, Error> {
    let resolver = AsyncResolver::tokio_from_system_conf().context(ServiceLookup { srv: srv.to_owned() })?;

    tracing::debug!(service = srv, "resolving service record");
    let mut records = resolver
        .srv_lookup(srv)
        .await
        .context(ServiceLookup { srv: srv.to_owned() })?
        .into_iter()
        .collect::<Vec<SRV>>();

    records.sort_by_key(|r| {
        let rng = rand::thread_rng().gen::<u16>() as u32;
        (r.priority(), Reverse(r.weight() as u32 * rng))
    });

    let addrs = records
        .iter()
        .filter_map(|r| (r.target().to_utf8(), r.port()).to_socket_addrs().ok())
        .flatten()
        .collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        Err(Error::ServiceAddrs { srv: srv.to_owned() })
    } else {
        Ok(addrs)
    }
}
