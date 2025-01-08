/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::conf::config;

use libgssapi::{context::CtxFlags, credential::Cred, error::Error as GssError, name::Name, oid::*, util::Buf};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{ops::Deref, string::FromUtf8Error};

pub use libgssapi::{
    context::{ClientCtx, SecurityContext, ServerCtx},
    credential::CredUsage,
};

pub static MECH: &Oid = &GSS_MECH_KRB5;

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to resolve principal `{princ}`"))]
    InvalidPrincipal { princ: String, source: GssError },
    #[snafu(display("Failed to decode principal"))]
    DecodePrincipal { source: FromUtf8Error },
    #[snafu(display("Failed to acquire credentials"))]
    BadCreds { source: GssError },
    #[snafu(display("Failed to acquire credentials for `{princ}`"))]
    BadS4UCreds { princ: String, source: GssError },
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

pub enum Principal<'a> {
    Common(&'a str),
    Enterprise(&'a str),
}

impl<'a> Deref for Principal<'a> {
    type Target = str;

    fn deref(&self) -> &'a Self::Target {
        match self {
            Self::Common(s) => s,
            Self::Enterprise(s) => s,
        }
    }
}

#[derive(PartialEq)]
pub enum DelegatePolicy {
    None,
    Delegate,
    ForceDelegate,
}

pub fn new_server_ctx(serv_princ: Principal) -> Result<ServerCtx, Error> {
    let mut mechs = OidSet::new().unwrap();
    mechs.add(MECH).unwrap();

    let serv_princ = Name::new(serv_princ.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .and_then(|s| s.canonicalize(Some(MECH)))
        .context(InvalidPrincipal {
            princ: serv_princ.to_string(),
        })?;

    tracing::debug!(source = %serv_princ, "initializing GSS context");
    let cred = Cred::acquire(Some(&serv_princ), None, CredUsage::Accept, Some(&mechs))?;

    Ok(ServerCtx::new(cred.into()))
}

fn principal_realm_to_upper(princ: &Principal) -> String {
    let mut iter = princ.chars();
    let mut buf = String::new();
    let mut first_at = true;

    while let Some(c) = iter.next() {
        buf.push(c);
        match c {
            '\\' => iter.next().map_or((), |c| buf.push(c)),
            '@' if matches!(princ, Principal::Enterprise(_)) && first_at => first_at = false,
            '@' => break,
            _ => (),
        };
    }
    iter.flat_map(|c| c.to_uppercase()).for_each(|c| buf.push(c));

    buf
}

fn principal_kind_to_oid(princ: &Principal) -> &'static Oid {
    match princ {
        Principal::Common(_) => &GSS_NT_KRB5_PRINCIPAL,
        Principal::Enterprise(_) => &GSS_NT_KRB5_ENTERPRISE_NAME,
    }
}

pub fn new_client_ctx(
    clnt_princ: Option<Principal>,
    serv_princ: Principal,
    delegate: DelegatePolicy,
) -> Result<ClientCtx, Error> {
    let mut mechs = OidSet::new().unwrap();
    mechs.add(MECH).unwrap();

    let mut flags = CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_CONF_FLAG | CtxFlags::GSS_C_INTEG_FLAG;
    match delegate {
        DelegatePolicy::ForceDelegate if config().policy.force_delegate => {
            flags |= CtxFlags::GSS_C_DELEG_POLICY_FLAG | CtxFlags::GSS_C_DELEG_FLAG
        }
        DelegatePolicy::Delegate | DelegatePolicy::ForceDelegate => flags |= CtxFlags::GSS_C_DELEG_POLICY_FLAG,
        _ => (),
    };

    let serv_princ = Name::new(serv_princ.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .and_then(|s| s.canonicalize(Some(MECH)))
        .context(InvalidPrincipal {
            princ: serv_princ.to_string(),
        })?;

    tracing::debug!(target = %serv_princ, "initializing GSS context");
    let mut cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&mechs)).context(BadCreds)?;

    if let Some(clnt_princ) = clnt_princ {
        let clnt_princ = Name::new(
            principal_realm_to_upper(&clnt_princ).as_bytes(),
            Some(principal_kind_to_oid(&clnt_princ)),
        )
        .context(InvalidPrincipal {
            princ: clnt_princ.to_string(),
        })?;

        tracing::debug!(principal = %clnt_princ, "impersonating principal");
        cred = cred
            .impersonate(&clnt_princ, None, CredUsage::Initiate, Some(&mechs))
            .context(BadS4UCreds {
                princ: clnt_princ.to_string(),
            })?;
    }

    Ok(ClientCtx::new(cred.into(), serv_princ, flags, Some(MECH)))
}

pub trait SecurityContextExt {
    fn source_principal(&mut self) -> Result<String, Error>;
    fn source_username(&mut self) -> Result<String, Error>;
}

impl<T: SecurityContext> SecurityContextExt for T {
    fn source_principal(&mut self) -> Result<String, Error> {
        let princ = self.source_name().and_then(|n| n.display_name())?;
        String::from_utf8(princ.to_vec()).context(DecodePrincipal)
    }

    fn source_username(&mut self) -> Result<String, Error> {
        let princ = self.source_name().and_then(|n| n.local_name(Some(MECH)))?;
        String::from_utf8(princ.to_vec()).context(DecodePrincipal)
    }
}
