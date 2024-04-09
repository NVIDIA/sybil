/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::trace::*;

use netaddr2::NetAddr;
use regex_lite::Regex;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::{env, fmt, path::Path};

const DEFAULT_TKT_CIPHER: &str = "aes256-sha1";
const DEFAULT_TKT_FLAGS: &str = "FR";
const DEFAULT_TKT_LIFETIME: &str = "10h";
const DEFAULT_TKT_RENEW_LIFETIME: &str = "7d";

lazy_static::lazy_static! {
    pub static ref CONFIG: Config = new_config();
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Permissions {
    pub kinit: bool,
    pub read: bool,
    pub write: bool,
    pub world: bool,
}

#[serde_as]
#[derive(Deserialize)]
pub struct Acl {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub principal: Option<Regex>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub user: Option<Regex>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub group: Option<Regex>,
    pub hosts: Option<Vec<NetAddr>>,
    pub permissions: Permissions,
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Ticket {
    pub cipher: String,
    pub flags: String,
    pub lifetime: String,
    pub renew_lifetime: String,
    pub cross_realm: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub use_fully_qualified_username: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub policy: Policy,
    pub ticket: Ticket,
    pub acl: Vec<Acl>,
}

impl Default for Ticket {
    fn default() -> Self {
        Self {
            cipher: DEFAULT_TKT_CIPHER.to_owned(),
            flags: DEFAULT_TKT_FLAGS.to_owned(),
            lifetime: DEFAULT_TKT_LIFETIME.to_owned(),
            renew_lifetime: DEFAULT_TKT_RENEW_LIFETIME.to_owned(),
            cross_realm: Default::default(),
        }
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.kinit { "k" } else { "-" },
            if self.read { "r" } else { "-" },
            if self.write { "w" } else { "-" },
            if self.world { "W" } else { "-" }
        )
    }
}

fn new_config() -> Config {
    let mut conf = config::Config::builder();

    if let Some(src) = option_env!("PREFIX")
        .map_or("/".as_ref(), Path::new)
        .join("etc/sybil")
        .to_str()
        .map(|f| config::File::with_name(f).required(false))
    {
        conf = conf.add_source(src);
    }

    if let Some(src) = env::var("SYBIL_CONFIG")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(|f| config::File::with_name(&f).required(false))
    {
        conf = conf.add_source(src);
    }

    conf.add_source(
        config::Environment::with_prefix("SYBIL")
            .try_parsing(true)
            .list_separator(","),
    )
    .build()
    .and_then(config::Config::try_deserialize)
    .unwrap_or_else(|error| {
        tracing::warn!(%error, "could not load configuration");
        Config::default()
    })
}

pub fn load_config() {
    tracing::info!(
        use_fully_qualified_username = %CONFIG.policy.use_fully_qualified_username,
        "policy configuration"
    );
    tracing::info!(
        cipher = %CONFIG.ticket.cipher,
        flags = %CONFIG.ticket.flags,
        lifetime = %CONFIG.ticket.cipher,
        renew_lifetime = %CONFIG.ticket.renew_lifetime,
        cross_realm = CONFIG.ticket.cross_realm.display(),
        "ticket configuration"
    );
    CONFIG.acl.iter().for_each(|r| {
        tracing::info!(
            principal = r.principal.display(),
            user = r.user.display(),
            group = r.group.display(),
            hosts = r.hosts.as_ref().map(|h| h.iter().map(ToString::to_string).collect::<Vec<_>>()).debug(),
            permissions = %r.permissions,
            "registered acl rule"
        )
    });
}
