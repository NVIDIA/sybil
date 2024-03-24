use netaddr2::NetAddr;
use serde::Deserialize;
use std::path::Path;

const DEFAULT_TKT_CIPHER: &str = "aes256-sha1";
const DEFAULT_TKT_FLAGS: &str = "FRI";
const DEFAULT_TKT_LIFE: &str = "10h";
const DEFAULT_TKT_RENEW_LIFE: &str = "7d";

lazy_static::lazy_static! {
    pub static ref CONFIG: Config = config::Config::builder()
        .add_source(
            config::File::with_name(
                &option_env!("PREFIX").map_or("/".as_ref(), Path::new).join("etc/sybil").to_string_lossy(),
            )
            .required(false),
        )
        .add_source(
            config::Environment::with_prefix("SYBIL").try_parsing(true).list_separator(","),
        )
        .build()
        .and_then(config::Config::try_deserialize)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "could not load configuration");
            Config::default()
        });
}

#[derive(Deserialize)]
pub struct Config {
    pub tkt_cipher: String,
    pub tkt_flags: String,
    pub tkt_life: String,
    pub tkt_renew_life: String,
    pub allow_networks: Vec<NetAddr>,
    pub allow_realms: Vec<String>,
    pub allow_groups: Vec<String>,
    pub strip_domain: bool,
    pub cross_realm: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tkt_cipher: DEFAULT_TKT_CIPHER.to_owned(),
            tkt_flags: DEFAULT_TKT_FLAGS.to_owned(),
            tkt_life: DEFAULT_TKT_LIFE.to_owned(),
            tkt_renew_life: DEFAULT_TKT_RENEW_LIFE.to_owned(),
            allow_networks: Default::default(),
            allow_realms: Default::default(),
            allow_groups: Default::default(),
            strip_domain: Default::default(),
            cross_realm: Default::default(),
        }
    }
}

pub fn load_config() {
    tracing::info!(
        config.tkt_cipher = ?CONFIG.tkt_cipher,
        config.tkt_flags = ?CONFIG.tkt_flags,
        config.tkt_life = ?CONFIG.tkt_life,
        config.tkt_renew_life = ?CONFIG.tkt_renew_life,
        config.allow_networks = ?CONFIG.allow_networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        config.allow_realms = ?CONFIG.allow_realms,
        config.allow_groups = ?CONFIG.allow_groups,
        config.strip_domain = ?CONFIG.strip_domain,
        config.cross_realm = ?CONFIG.cross_realm,
        "loaded configuration"
    );
}
