// SPDX-License-Identifier: GPL-3.0-or-later
//! Meshtastic config sync handler for LICHEN bridge.
//!
//! Handles AdminMessage config requests from Meshtastic apps and returns
//! LICHEN node configuration in Meshtastic format.

use crate::{
    admin_message::PayloadVariant, channel, config, AdminConfigType, AdminMessage, Channel,
    ChannelSettings, Config, DeviceMetadata, HardwareModel, User,
};

// LoRa spreading factors (SF7-SF12).
// Higher SF = longer range, slower data rate, more airtime.
const SF_7: u8 = 7;
const SF_8: u8 = 8;
const SF_9: u8 = 9;
const SF_10: u8 = 10;
const SF_11: u8 = 11;
const SF_12: u8 = 12;

// LoRa bandwidths in Hz.
// Narrower bandwidth = better sensitivity, slower data rate.
const BW_125_KHZ: u32 = 125_000;
const BW_250_KHZ: u32 = 250_000;
const BW_500_KHZ: u32 = 500_000;

/// LICHEN node configuration that can be mapped to Meshtastic format.
#[derive(Debug, Clone)]
pub struct LichenConfig {
    /// Node ID (32-bit).
    pub node_id: u32,
    /// Long name for display.
    pub long_name: String,
    /// Short name (4 chars max).
    pub short_name: String,
    /// LoRa spreading factor (7-12).
    pub spreading_factor: u8,
    /// Bandwidth in Hz.
    pub bandwidth: u32,
    /// Coding rate denominator (5-8).
    pub coding_rate: u8,
    /// Transmit power in dBm.
    pub tx_power: i8,
    /// Frequency in Hz.
    pub frequency: u32,
    /// Channel name.
    pub channel_name: String,
    /// Channel PSK (empty = no encryption, 16 or 32 bytes).
    pub channel_psk: Vec<u8>,
    /// Firmware version string.
    pub firmware_version: String,
}

impl Default for LichenConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            long_name: "LICHEN Node".into(),
            short_name: "LICH".into(),
            spreading_factor: 10,
            bandwidth: 125_000,
            coding_rate: 5,
            tx_power: 14,
            frequency: 915_000_000,
            channel_name: "LICHEN".into(),
            channel_psk: Vec::new(),
            firmware_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Config handler for Meshtastic admin requests.
#[derive(Debug, Clone)]
pub struct ConfigHandler {
    config: LichenConfig,
}

impl ConfigHandler {
    /// Create a new config handler with the given LICHEN configuration.
    pub fn new(config: LichenConfig) -> Self {
        Self { config }
    }

    /// Handle an AdminMessage request and return a response.
    ///
    /// Returns `Some(AdminMessage)` with the response, or `None` if the
    /// request type is not supported or is a set/command that doesn't
    /// need a response.
    pub fn handle_admin_request(&self, msg: &AdminMessage) -> Option<AdminMessage> {
        let payload = msg.payload_variant.as_ref()?;

        match payload {
            PayloadVariant::GetChannelRequest(index) => {
                Some(self.make_channel_response(*index))
            }
            PayloadVariant::GetOwnerRequest(true) => {
                Some(self.make_owner_response())
            }
            PayloadVariant::GetConfigRequest(config_type) => {
                self.make_config_response(*config_type)
            }
            PayloadVariant::GetDeviceMetadataRequest(true) => {
                Some(self.make_metadata_response())
            }
            // Set and command variants - log and ignore
            PayloadVariant::SetChannel(_)
            | PayloadVariant::SetOwner(_)
            | PayloadVariant::SetConfig(_)
            | PayloadVariant::RebootSeconds(_)
            | PayloadVariant::FactoryReset(_)
            | PayloadVariant::NodedbReset(_) => None,
            // Bool requests with false value - ignore
            PayloadVariant::GetOwnerRequest(false)
            | PayloadVariant::GetDeviceMetadataRequest(false) => None,
            // Response variants - we don't process these, they're for clients
            PayloadVariant::GetChannelResponse(_)
            | PayloadVariant::GetOwnerResponse(_)
            | PayloadVariant::GetConfigResponse(_)
            | PayloadVariant::GetDeviceMetadataResponse(_) => None,
        }
    }

    fn make_channel_response(&self, index: u32) -> AdminMessage {
        // IMPORTANT: Meshtastic channel indexing quirk
        //
        // GetChannelRequest uses 1-indexed channel numbers (1 = primary, 2 = secondary, etc.)
        // but GetChannelResponse.Channel.index uses 0-indexed (0 = primary, 1 = secondary).
        //
        // This asymmetry exists in the Meshtastic firmware (device/RadioInterface.cpp) and
        // is preserved by apps like the Android/iOS clients. Getting this wrong causes apps
        // to display channels incorrectly or fail to sync.
        //
        // Reference: https://github.com/meshtastic/protobufs (AdminMessage, Channel)
        let channel_index = index.saturating_sub(1) as i32;

        let (role, settings) = if channel_index == 0 {
            // Primary channel with LICHEN config
            //
            // `channel_num` is deprecated in Meshtastic protobufs (channel.proto field 1)
            // but older Meshtastic clients (pre-2.0) still expect it to be set. We include
            // it for backward compatibility until we can confirm all target clients have
            // migrated to using Channel.index instead. Can be removed once Meshtastic 2.x
            // is the minimum supported client version.
            #[allow(deprecated)]
            (
                channel::Role::Primary as i32,
                Some(ChannelSettings {
                    channel_num: 0,
                    psk: self.config.channel_psk.clone(),
                    name: self.config.channel_name.clone(),
                    id: self.config.node_id,
                    uplink_enabled: false,
                    downlink_enabled: false,
                }),
            )
        } else {
            // Secondary channels disabled
            (channel::Role::Disabled as i32, None)
        };

        AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetChannelResponse(Channel {
                index: channel_index,
                settings,
                role,
            })),
        }
    }

    /// Build owner response with User info.
    ///
    /// `macaddr` is deprecated in Meshtastic protobufs (mesh.proto User field 4) because
    /// MAC addresses leak device identity and are not meaningful for mesh routing. Modern
    /// Meshtastic uses the node ID (derived from hardware serial) instead. We still include
    /// the field (empty) for wire compatibility with older clients that may expect it. Can
    /// be omitted entirely once Meshtastic 2.x is the minimum supported client version.
    #[allow(deprecated)]
    fn make_owner_response(&self) -> AdminMessage {
        AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetOwnerResponse(User {
                id: format!("!{:08x}", self.config.node_id),
                long_name: self.config.long_name.clone(),
                short_name: self.config.short_name.clone(),
                macaddr: Vec::new(),
                hw_model: HardwareModel::PrivateHw as i32,
                is_licensed: false,
                role: config::device_config::Role::Client as i32,
                public_key: Vec::new(),
                is_unmessagable: None,
            })),
        }
    }

    fn make_config_response(&self, config_type: i32) -> Option<AdminMessage> {
        let config_type = AdminConfigType::try_from(config_type).ok()?;

        let payload = match config_type {
            AdminConfigType::DeviceConfig => {
                config::PayloadVariant::Device(self.make_device_config())
            }
            AdminConfigType::LoraConfig => {
                config::PayloadVariant::Lora(self.make_lora_config())
            }
            // Unsupported config types - return empty device config
            _ => config::PayloadVariant::Device(config::DeviceConfig::default()),
        };

        Some(AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetConfigResponse(Config {
                payload_variant: Some(payload),
            })),
        })
    }

    fn make_device_config(&self) -> config::DeviceConfig {
        config::DeviceConfig {
            role: config::device_config::Role::Client as i32,
            serial_enabled: true,
            debug_log_enabled: false,
            button_gpio: 0,
            buzzer_gpio: 0,
            rebroadcast_mode: config::device_config::RebroadcastMode::All as i32,
            node_info_broadcast_secs: 900, // 15 min default
            double_tap_as_button_press: false,
            is_managed: false,
            disable_triple_click: false,
            tzdef: String::new(),
            led_heartbeat_disabled: false,
        }
    }

    fn make_lora_config(&self) -> config::LoRaConfig {
        // Map LICHEN bandwidth (Hz) to Meshtastic format (kHz)
        let bandwidth = match self.config.bandwidth {
            BW_125_KHZ => 125,
            BW_250_KHZ => 250,
            BW_500_KHZ => 500,
            bw => (bw / 1000) as u32,
        };

        // Map frequency to Meshtastic region
        let region = match self.config.frequency {
            868_000_000..=868_999_999 => config::lo_ra_config::RegionCode::Eu868,
            433_000_000..=434_999_999 => config::lo_ra_config::RegionCode::Eu433,
            915_000_000..=928_000_000 => config::lo_ra_config::RegionCode::Us,
            _ => config::lo_ra_config::RegionCode::Unset,
        };

        // Map LICHEN (SF, bandwidth) to closest Meshtastic modem preset.
        //
        // Meshtastic presets are defined in config.proto (ModemPreset enum).
        // Each preset corresponds to specific LoRa parameters:
        //   - SF (spreading factor): 7-12, higher = longer range, slower
        //   - BW (bandwidth): 125/250/500 kHz, narrower = better sensitivity
        //
        // Reference: https://meshtastic.org/docs/overview/radio-settings/
        let modem_preset = match (self.config.spreading_factor, self.config.bandwidth) {
            (SF_12, BW_125_KHZ) => config::lo_ra_config::ModemPreset::VeryLongSlow,
            (SF_11, BW_125_KHZ) => config::lo_ra_config::ModemPreset::LongSlow,
            (SF_10, BW_125_KHZ) => config::lo_ra_config::ModemPreset::LongFast,
            (SF_9, BW_125_KHZ) => config::lo_ra_config::ModemPreset::MediumSlow,
            (SF_8, BW_125_KHZ) => config::lo_ra_config::ModemPreset::MediumFast,
            (SF_7, BW_125_KHZ) => config::lo_ra_config::ModemPreset::ShortSlow,
            (SF_7, BW_250_KHZ) => config::lo_ra_config::ModemPreset::ShortFast,
            (SF_7, BW_500_KHZ) => config::lo_ra_config::ModemPreset::ShortTurbo,
            _ => config::lo_ra_config::ModemPreset::LongFast,
        };

        config::LoRaConfig {
            use_preset: true,
            modem_preset: modem_preset as i32,
            bandwidth,
            spread_factor: self.config.spreading_factor as u32,
            coding_rate: self.config.coding_rate as u32,
            frequency_offset: 0.0,
            region: region as i32,
            hop_limit: 3,
            tx_enabled: true,
            tx_power: self.config.tx_power as i32,
            channel_num: 0,
            override_duty_cycle: false,
            sx126x_rx_boosted_gain: false,
            override_frequency: 0.0,
            pa_fan_disabled: false,
            ignore_incoming: false,
            ignore_mqtt: true,
        }
    }

    fn make_metadata_response(&self) -> AdminMessage {
        AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetDeviceMetadataResponse(DeviceMetadata {
                firmware_version: self.config.firmware_version.clone(),
                device_state_version: 1,
                can_shutdown: false,
                has_wifi: false,
                has_bluetooth: true,
                has_ethernet: false,
                platform_type: crate::device_metadata::PlatformType::PlatformNative as i32,
                hw_model: HardwareModel::PrivateHw as i32,
                has_remote_hardware: false,
                has_pkc: false,
                excluded_modules: None,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_request() {
        let handler = ConfigHandler::new(LichenConfig::default());
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetChannelRequest(1)),
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetChannelResponse(ch) => {
                assert_eq!(ch.index, 0);
                assert_eq!(ch.role, channel::Role::Primary as i32);
                assert!(ch.settings.is_some());
                let settings = ch.settings.unwrap();
                assert_eq!(settings.name, "LICHEN");
            }
            _ => panic!("unexpected response type"),
        }
    }

    #[test]
    fn test_owner_request() {
        let mut config = LichenConfig::default();
        config.node_id = 0xDEADBEEF;
        config.long_name = "Test Node".into();
        config.short_name = "TEST".into();

        let handler = ConfigHandler::new(config);
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetOwnerRequest(true)),
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetOwnerResponse(user) => {
                assert_eq!(user.id, "!deadbeef");
                assert_eq!(user.long_name, "Test Node");
                assert_eq!(user.short_name, "TEST");
            }
            _ => panic!("unexpected response type"),
        }
    }

    #[test]
    fn test_lora_config_request() {
        let handler = ConfigHandler::new(LichenConfig::default());
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetConfigRequest(
                AdminConfigType::LoraConfig as i32,
            )),
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetConfigResponse(cfg) => match cfg.payload_variant.unwrap() {
                config::PayloadVariant::Lora(lora) => {
                    assert_eq!(lora.spread_factor, 10);
                    assert_eq!(lora.bandwidth, 125);
                    assert_eq!(lora.coding_rate, 5);
                    assert_eq!(lora.tx_power, 14);
                    assert!(lora.tx_enabled);
                }
                _ => panic!("unexpected config type"),
            },
            _ => panic!("unexpected response type"),
        }
    }

    #[test]
    fn test_device_metadata_request() {
        let handler = ConfigHandler::new(LichenConfig::default());
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetDeviceMetadataRequest(true)),
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetDeviceMetadataResponse(meta) => {
                assert!(!meta.firmware_version.is_empty());
                assert!(meta.has_bluetooth);
                assert!(!meta.has_wifi);
            }
            _ => panic!("unexpected response type"),
        }
    }

    #[test]
    fn test_unsupported_config_returns_default() {
        let handler = ConfigHandler::new(LichenConfig::default());
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetConfigRequest(
                AdminConfigType::NetworkConfig as i32,
            )),
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetConfigResponse(cfg) => {
                // Should return empty device config for unsupported types
                assert!(cfg.payload_variant.is_some());
            }
            _ => panic!("unexpected response type"),
        }
    }

    #[test]
    fn test_set_commands_return_none() {
        let handler = ConfigHandler::new(LichenConfig::default());

        // Set channel
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::SetChannel(Channel::default())),
        };
        assert!(handler.handle_admin_request(&request).is_none());

        // Reboot
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::RebootSeconds(5)),
        };
        assert!(handler.handle_admin_request(&request).is_none());
    }

    #[test]
    fn test_disabled_secondary_channel() {
        let handler = ConfigHandler::new(LichenConfig::default());
        let request = AdminMessage {
            session_passkey: Vec::new(),
            payload_variant: Some(PayloadVariant::GetChannelRequest(2)), // Secondary
        };

        let response = handler.handle_admin_request(&request).unwrap();
        match response.payload_variant.unwrap() {
            PayloadVariant::GetChannelResponse(ch) => {
                assert_eq!(ch.index, 1);
                assert_eq!(ch.role, channel::Role::Disabled as i32);
                assert!(ch.settings.is_none());
            }
            _ => panic!("unexpected response type"),
        }
    }
}
