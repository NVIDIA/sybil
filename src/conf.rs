/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::trace::*;
use crate::{SYBIL_ENV_CONFIG, SYBIL_ENV_USER};

use netaddr2::NetAddr;
use regex_lite::Regex;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::{env, fmt, path::Path, sync::OnceLock};

const DEFAULT_TKT_CIPHER: &str = "aes256-sha1";
const DEFAULT_TKT_FLAGS: &str = "FR";
const DEFAULT_TKT_LIFETIME: &str = "10h";
const DEFAULT_TKT_RENEWABLE_LIFETIME: &str = "7d";
const DEFAULT_TKT_MINIMUM_LIFETIME: &str = "5m";

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Permissions {
    pub kinit: bool,
    pub list: bool,
    pub read: bool,
    pub write: bool,
    pub masquerade: bool,
}

#[serde_as]
#[derive(Default, Deserialize)]
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

#[derive(Deserialize)]
#[serde(default)]
pub struct Ticket {
    pub cipher: String,
    pub flags: String,
    pub lifetime: String,
    pub renewable_lifetime: String,
    pub minimum_lifetime: String,
    pub fully_qualified_user: bool,
    pub cross_realm: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub force_delegate: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server_addrs: Vec<String>,
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
            renewable_lifetime: DEFAULT_TKT_RENEWABLE_LIFETIME.to_owned(),
            minimum_lifetime: DEFAULT_TKT_MINIMUM_LIFETIME.to_owned(),
            fully_qualified_user: false,
            cross_realm: false,
        }
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            if self.kinit { "k" } else { "-" },
            if self.list { "l" } else { "-" },
            if self.read { "r" } else { "-" },
            if self.write { "w" } else { "-" },
            if self.masquerade { "m" } else { "-" }
        )
    }
}

pub fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();

    CONFIG.get_or_init(|| {
        let mut conf = config::Config::builder();

        if let Some(src) = option_env!("PREFIX")
            .map_or("/".as_ref(), Path::new)
            .join("etc/sybil")
            .to_str()
            .map(|f| config::File::with_name(f).required(false))
        {
            conf = conf.add_source(src);
        }

        if let Some(src) = env::var(SYBIL_ENV_CONFIG)
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(|f| config::File::with_name(&f).required(false))
        {
            conf = conf.add_source(src);
        }

        conf.add_source(
            config::Environment::with_prefix("SYBIL")
                .try_parsing(true)
                .list_separator(",")
                .with_list_parse_key("server_addrs"),
        )
        .build()
        .and_then(config::Config::try_deserialize)
        .unwrap_or_else(|err| {
            tracing::warn!(error = err.chain(), "could not load configuration");
            Config::default()
        })
    })
}

pub fn load_server_config() {
    tracing::info!(
        cipher = %config().ticket.cipher,
        flags = %config().ticket.flags,
        lifetime = %config().ticket.lifetime,
        renewable_lifetime = %config().ticket.renewable_lifetime,
        minimum_lifetime = %config().ticket.minimum_lifetime,
        fully_qualified_user = %config().ticket.fully_qualified_user,
        cross_realm = %config().ticket.cross_realm,
        "ticket configuration"
    );
    config().acl.iter().for_each(|r| {
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

pub fn load_client_config() {
    if env::var(SYBIL_ENV_USER).is_ok() {
        _ = config();
        return;
    }

    tracing::info!(
        force_delegate = %config().policy.force_delegate,
        "policy configuration"
    );
}
