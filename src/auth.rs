/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::conf::{self, CONFIG};
use crate::gss::{self, SecurityContextExt};
use crate::trace::*;

use bitflags::bitflags;
use netaddr2::Contains;
use nix::unistd::{self, User};
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
    pub fn username(&self) -> Option<&str> {
        let (_, realm) = self.principal.rsplit_once('@').unzip();

        if CONFIG.policy.use_fully_qualified_username || realm.is_none() {
            self.user.as_ref().map(|u| u.name.as_str())
        } else {
            self.user.as_ref().map(|u| {
                u.name
                    .strip_suffix(&format!("@{}", realm.unwrap().to_lowercase()))
                    .unwrap_or(u.name.as_str())
            })
        }
    }
}

#[rustfmt::skip]
pub fn authorize(gss: &mut impl gss::SecurityContext, peer: &IpAddr, perms: Permissions) -> Option<Identity> {
    tracing::debug!(%perms, "performing authorization checks");

    let principal = gss.source_principal().map_or_else(
        |error| { tracing::error!(%error, "could not retrieve source principal"); None },
        Into::into,
    )?;

    let user = gss.source_username().map_or_else(
        |error| { tracing::debug!(%error, "could not retrieve source username"); None },
        |username| match unistd::User::from_name(&username) {
            Err(_) | Ok(None) => { tracing::debug!(%username, "could not lookup user"); None },
            Ok(user) => user,
        },
    );

    let groups = user.as_ref().and_then(|u| {
        unistd::getgrouplist(&CString::new(u.name.as_str()).unwrap(), u.gid).map_or_else(
            |error| { tracing::debug!(%error, username = %u.name, "could not lookup groups"); None },
            |groups| Some(
                groups
                    .into_iter()
                    .filter_map(|g| unistd::Group::from_gid(g).ok().flatten().map(|g| g.name))
                    .collect(),
            ),
        )
    });

    let id = Identity { principal, user, groups };

    for (r, rule) in CONFIG.acl.iter().enumerate() {
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
            if regex.as_str().trim().is_empty() || id.username().map_or(true, |u| !regex.is_match(u)) {
                tracing::debug!(rule = r, user = id.username().display(), "acl rule skipped due to user policy");
                continue;
            }
        }
        if let Some(regex) = &rule.group {
            if regex.as_str().trim().is_empty() || id.groups.as_ref().map_or(true, |g| !g.iter().any(|n| regex.is_match(n))) {
                tracing::debug!(rule = r, groups = id.groups.debug(), "acl rule skipped due to group policy");
                continue;
            }
        }
        tracing::debug!(principal = %id.principal, user = id.username().display(), "successfully authorized");
        return Some(id);
    }
    tracing::debug!(principal = %id.principal, user = id.username().display(), "permission denied");
    None
}
