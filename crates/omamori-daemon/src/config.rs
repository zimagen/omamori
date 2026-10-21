use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Approval {
    #[default]
    PerType,
    Auto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub approval: Approval,
    pub host_name: String,
    pub adapter: String,
    pub sudo: bool,
    pub lock: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            approval: Approval::PerType,
            host_name: String::new(),
            adapter: String::new(),
            sudo: true,
            lock: true,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).context("invalid config")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).context("read config"),
        };
        if config.host_name.is_empty() {
            config.host_name = fs::read_to_string("/proc/sys/kernel/hostname")
                .context("read hostname")?
                .trim()
                .to_owned();
        }
        Ok(config)
    }
}
