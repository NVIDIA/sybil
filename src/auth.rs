/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::conf::{self, config};
use crate::gss::{self, SecurityContextExt};
use crate::trace::*;

use bitflags::bitflags;
use netaddr2::Contains;
use nix::unistd::{self, Group, User};
use std::{ffi::CString, fmt, net::IpAddr};

bitflags! {
    #[derive(Default, Clone)]
    pub struct Permissions : u32 {
        const KINIT      = 1;
        const READ       = 1 << 1;
        const WRITE      = 1 << 2;
        const MASQUERADE = 1 << 3;
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl From<&conf::Permissions> for Permissions {
    fn from(perms: &conf::Permissions) -> Self {
        Self::default()
            | perms.kinit.then_some(Self::KINIT).unwrap_or_default()
            | perms.read.then_some(Self::READ).unwrap_or_default()
            | perms.write.then_some(Self::WRITE).unwrap_or_default()
            | perms.masquerade.then_some(Self::MASQUERADE).unwrap_or_default()
    }
}

pub struct Identity {
    pub principal: String,
    pub user: Option<User>,
    pub groups: Option<Vec<String>>,
}

impl Identity {
    pub fn principal_realm(&self) -> Option<&str> {
        self.principal.rsplit_once('@').unzip().1
    }

    pub fn username(&self, strip_realm: bool) -> Option<&str> {
        let username = self.user.as_ref().map(|u| u.name.as_str());

        if !strip_realm {
            return username;
        }
        match self.principal_realm() {
            Some(realm) => username.map(|u| u.strip_suffix(&format!("@{}", realm.to_lowercase())).unwrap_or(u)),
            None => username,
        }
    }
}

#[rustfmt::skip]
pub fn authorize(gss: &mut impl gss::SecurityContext, peer: &IpAddr, perms: Permissions) -> Option<Identity> {
    let principal = gss.source_principal().map_or_else(
        |err| { tracing::error!(error = err.chain(), "could not retrieve source principal"); None },
        Into::into,
    )?;

    tracing::debug!(%perms, %principal, "performing authorization checks");

    let user = gss.source_username().map_or_else(
        |err| { tracing::debug!(error = err.chain(), "could not retrieve source username"); None },
        |username| match User::from_name(&username) {
            Err(_) | Ok(None) => { tracing::debug!(%username, "could not lookup user"); None },
            Ok(user) => user,
        },
    );

    let groups = user.as_ref().and_then(|u| {
        unistd::getgrouplist(&CString::new(u.name.as_str()).unwrap(), u.gid).map_or_else(
            |err| { tracing::debug!(error = err.chain(), username = %u.name, "could not lookup groups"); None },
            |groups| Some(
                groups
                    .into_iter()
                    .filter_map(|g| Group::from_gid(g).ok().flatten().map(|g| g.name))
                    .collect(),
            ),
        )
    });

    let id = Identity { principal, user, groups };
    let username = id.user.as_ref().map(|u| &u.name);

    for (r, rule) in config().acl.iter().enumerate() {
        if let conf::Acl{principal: None, user: None, group: None, hosts: None, permissions: _} = rule {
            continue;
        }
        if !Permissions::from(&rule.permissions).contains(perms.clone()) {
            tracing::debug!(rule = r, %perms, "acl rule skipped due to permissions mismatch");
            continue;
        }

        if let Some(hosts) = &rule.hosts {
            if !hosts.iter().any(|h| h.contains(peer)) {
                tracing::debug!(rule = r, %peer, "acl rule skipped due to host policy");
                continue;
            }
        }
        if let Some(regex) = &rule.principal {
            if regex.as_str().trim().is_empty() || !regex.is_match(&id.principal) {
                tracing::debug!(rule = r, principal = %id.principal, "acl rule skipped due to principal policy");
                continue;
            }
        }
        if let Some(regex) = &rule.user {
            if regex.as_str().trim().is_empty() || username.map_or(true, |u| !regex.is_match(u)) {
                tracing::debug!(rule = r, user = username.display(), "acl rule skipped due to user policy");
                continue;
            }
        }
        if let Some(regex) = &rule.group {
            if regex.as_str().trim().is_empty() || id.groups.as_ref().map_or(true, |g| !g.iter().any(|n| regex.is_match(n))) {
                tracing::debug!(rule = r, groups = id.groups.debug(), "acl rule skipped due to group policy");
                continue;
            }
        }
        tracing::debug!(principal = %id.principal, user = username.display(), "successfully authorized");
        return Some(id);
    }
    tracing::debug!(principal = %id.principal, user = username.display(), "permission denied");
    None
}
