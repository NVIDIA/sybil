/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use libgssapi::{
    context::CtxFlags,
    credential::{Cred, CredUsage},
    error::Error as GssError,
    name::Name,
    oid::*,
    util::Buf,
};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{ops::Deref, string::FromUtf8Error};

pub use libgssapi::context::{ClientCtx, SecurityContext, ServerCtx};

static MECH: &Oid = &GSS_MECH_KRB5;

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to resolve principal `{princ}`"))]
    InvalidPrincipal { princ: String, source: GssError },
    #[snafu(display("Failed to decode principal"))]
    DecodePrincipal { source: FromUtf8Error },
    #[snafu(display("Failed to acquire host credentials"))]
    BadHostCreds { source: GssError },
    #[snafu(display("Failed to acquire credentials for `{princ}`"))]
    BadUserCreds { princ: String, source: GssError },
    #[snafu(display("Generic GSS failure"), context(false))]
    Generic { source: GssError },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token(Vec<u8>);

impl From<Buf> for Token {
    fn from(buf: Buf) -> Self {
        Self(buf.to_vec())
    }
}

impl Deref for Token {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

pub fn new_server_ctx(serv_princ: &str) -> Result<ServerCtx, Error> {
    let mut mechs = OidSet::new().unwrap();
    mechs.add(MECH).unwrap();

    let serv_princ = Name::new(serv_princ.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .and_then(|s| s.canonicalize(Some(MECH)))
        .context(InvalidPrincipal { princ: serv_princ })?;

    tracing::debug!(source = %serv_princ, "initializing GSS context");
    let cred = Cred::acquire(Some(&serv_princ), None, CredUsage::Accept, Some(&mechs))?;

    Ok(ServerCtx::new(cred))
}

pub fn new_client_ctx(clnt_princ: Option<&str>, serv_princ: &str) -> Result<ClientCtx, Error> {
    let mut mechs = OidSet::new().unwrap();
    mechs.add(MECH).unwrap();

    let serv_princ = Name::new(serv_princ.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .and_then(|s| s.canonicalize(Some(MECH)))
        .context(InvalidPrincipal { princ: serv_princ })?;

    tracing::debug!(target = %serv_princ, "initializing GSS context");
    let mut cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&mechs)).context(BadHostCreds)?;

    if let Some(clnt_princ) = clnt_princ {
        let clnt_princ = Name::new(clnt_princ.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))
            .context(InvalidPrincipal { princ: clnt_princ })?;

        tracing::debug!(princ = %clnt_princ, "impersonating principal");
        cred = cred
            .impersonate(&clnt_princ, None, CredUsage::Initiate, Some(&mechs))
            .context(BadUserCreds {
                princ: clnt_princ.to_string(),
            })?;
    }

    Ok(ClientCtx::new(
        Some(cred),
        serv_princ,
        CtxFlags::GSS_C_MUTUAL_FLAG,
        Some(MECH),
    ))
}

pub fn source_principal(ctx: &mut impl SecurityContext) -> Result<String, Error> {
    let princ = ctx.source_name().and_then(|n| n.display_name())?;
    String::from_utf8(princ.to_vec()).context(DecodePrincipal)
}

pub fn source_username(ctx: &mut impl SecurityContext) -> Result<String, Error> {
    let princ = ctx.source_name().and_then(|n| n.local_name(Some(MECH)))?;
    String::from_utf8(princ.to_vec()).context(DecodePrincipal)
}
