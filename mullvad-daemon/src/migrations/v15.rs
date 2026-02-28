use super::Result;
use mullvad_types::settings::SettingsVersion;

/// This migration adds the `ip_exclusions` field to `split_tunnel` settings.
/// This field holds a list of IP networks (CIDR notation) whose traffic should
/// bypass the VPN firewall.
pub fn migrate(settings: &mut serde_json::Value) -> Result<()> {
    if !version_matches(settings) {
        return Ok(());
    }

    log::info!("Migrating settings format to V16");

    add_ip_exclusions(settings);

    settings["settings_version"] = serde_json::json!(SettingsVersion::V16);

    Ok(())
}

fn add_ip_exclusions(settings: &mut serde_json::Value) -> Option<()> {
    let split_tunnel = settings
        .get_mut("split_tunnel")
        .and_then(|st| st.as_object_mut())?;

    if !split_tunnel.contains_key("ip_exclusions") {
        split_tunnel.insert(
            "ip_exclusions".to_string(),
            serde_json::json!([]),
        );
    }

    Some(())
}

fn version_matches(settings: &serde_json::Value) -> bool {
    settings
        .get("settings_version")
        .map(|version| version == SettingsVersion::V15 as u64)
        .unwrap_or(false)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_v15_to_v16_migration_adds_ip_exclusions() {
        let mut settings = json!({
            "settings_version": 15,
            "split_tunnel": {
                "enable_exclusions": false,
                "apps": []
            }
        });
        migrate(&mut settings).unwrap();
        assert_eq!(settings["settings_version"], 16);
        assert_eq!(settings["split_tunnel"]["ip_exclusions"], json!([]));
    }

    #[test]
    fn test_v15_to_v16_migration_preserves_existing_ip_exclusions() {
        let mut settings = json!({
            "settings_version": 15,
            "split_tunnel": {
                "enable_exclusions": true,
                "apps": [],
                "ip_exclusions": ["100.64.0.0/10"]
            }
        });
        migrate(&mut settings).unwrap();
        assert_eq!(settings["settings_version"], 16);
        assert_eq!(
            settings["split_tunnel"]["ip_exclusions"],
            json!(["100.64.0.0/10"])
        );
    }

    #[test]
    fn test_v15_to_v16_migration_no_split_tunnel() {
        let mut settings = json!({
            "settings_version": 15
        });
        migrate(&mut settings).unwrap();
        assert_eq!(settings["settings_version"], 16);
        // No split_tunnel key, so no ip_exclusions added (Linux settings)
        assert!(settings.get("split_tunnel").is_none());
    }

    #[test]
    fn test_v15_to_v16_migration_skips_wrong_version() {
        let mut settings = json!({
            "settings_version": 14,
            "split_tunnel": {
                "enable_exclusions": false,
                "apps": []
            }
        });
        migrate(&mut settings).unwrap();
        // Should not have changed
        assert_eq!(settings["settings_version"], 14);
        assert!(settings["split_tunnel"].get("ip_exclusions").is_none());
    }
}
