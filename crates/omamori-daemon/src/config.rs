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
    #[serde(deserialize_with = "deserialize_adv_interval")]
    pub adv_interval_ms: [u16; 2],
    pub sudo: bool,
    pub lock: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            approval: Approval::PerType,
            host_name: String::new(),
            adapter: String::new(),
            adv_interval_ms: [20, 30],
            sudo: true,
            lock: true,
        }
    }
}

fn deserialize_adv_interval<'de, D>(deserializer: D) -> std::result::Result<[u16; 2], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<i64>::deserialize(deserializer)?;
    if values.len() != 2
        || values.iter().any(|v| !(20..=10240).contains(v))
        || values[0] > values[1]
    {
        return Err(serde::de::Error::custom(
            "adv_interval_ms must contain two integers in 20..=10240 with min <= max",
        ));
    }
    Ok([values[0] as u16, values[1] as u16])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertising_interval_defaults_and_valid_values() {
        assert_eq!(Config::default().adv_interval_ms, [20, 30]);
        assert_eq!(
            toml::from_str::<Config>("").unwrap().adv_interval_ms,
            [20, 30]
        );
        for values in [[20, 10240], [100, 200], [30, 30]] {
            let text = format!("adv_interval_ms = {values:?}");
            assert_eq!(
                toml::from_str::<Config>(&text).unwrap().adv_interval_ms,
                values
            );
        }
    }

    #[test]
    fn advertising_interval_rejects_invalid_values() {
        for value in [
            "[30, 20]",
            "[19, 30]",
            "[20, 10241]",
            "[-1, 30]",
            "[20]",
            "[20, 30, 40]",
            "[20.0, 30]",
            "[\"20\", 30]",
        ] {
            let error = toml::from_str::<Config>(&format!("adv_interval_ms = {value}"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("adv_interval_ms"), "{error}");
        }
    }
}
