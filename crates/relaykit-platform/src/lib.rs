use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformProfile {
    pub os: &'static str,
    pub family: &'static str,
    pub default_shell: &'static str,
    pub likely_ssh_target: &'static str,
    pub likely_rdp_target: Option<&'static str>,
}

pub fn current_platform() -> PlatformProfile {
    PlatformProfile {
        os: std::env::consts::OS,
        family: std::env::consts::FAMILY,
        default_shell: default_shell(),
        likely_ssh_target: "127.0.0.1:22",
        likely_rdp_target: likely_rdp_target(),
    }
}

fn default_shell() -> &'static str {
    if cfg!(windows) {
        "powershell"
    } else {
        "sh"
    }
}

fn likely_rdp_target() -> Option<&'static str> {
    if cfg!(windows) {
        Some("127.0.0.1:3389")
    } else {
        None
    }
}
