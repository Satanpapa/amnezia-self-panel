use std::{env, fs, path::Path, time::Duration};

use async_trait::async_trait;
use bollard::Docker;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub mode: &'static str,
    pub available: bool,
    pub engine: &'static str,
    pub message: String,
    /// False until protocol-aware VPN lifecycle operations are implemented.
    pub can_manage_vpn: bool,
}

/// Boundary between the HTTP/API layer and the process/container runtime.
/// Implementations must never execute user-provided shell fragments.
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    async fn status(&self) -> RuntimeStatus;
}

/// Safe local adapter used by default. It never attempts to start VPN services.
#[derive(Debug, Default)]
pub struct PreviewRuntime;

#[async_trait]
impl RuntimeAdapter for PreviewRuntime {
    async fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            mode: "preview",
            available: true,
            engine: "none",
            message: "Preview mode: metadata is stored in SQLite; no VPN process or container is running.".into(),
            can_manage_vpn: false,
        }
    }
}

/// Read-only Docker connectivity adapter. This intentionally does not create,
/// start, stop, or remove containers; those operations will be added only with
/// protocol-specific validation and lifecycle tests.
pub struct DockerRuntime {
    docker: Option<Docker>,
}

impl DockerRuntime {
    pub fn new() -> Self {
        let docker = match Docker::connect_with_local_defaults() {
            Ok(client) => Some(client),
            Err(error) => {
                tracing::warn!("Docker client could not be initialized: {error}");
                None
            }
        };
        Self { docker }
    }
}

#[async_trait]
impl RuntimeAdapter for DockerRuntime {
    async fn status(&self) -> RuntimeStatus {
        let Some(docker) = &self.docker else {
            return RuntimeStatus {
                mode: "docker",
                available: false,
                engine: "docker",
                message: "Docker socket is unavailable. Check that Docker is installed and the panel process can access its socket.".into(),
                can_manage_vpn: false,
            };
        };

        let ping = tokio::time::timeout(Duration::from_secs(3), docker.ping()).await;
        let (available, message) = match ping {
            Ok(Ok(_)) => (
                true,
                "Docker daemon is reachable. VPN container lifecycle is not enabled yet.".to_string(),
            ),
            Ok(Err(error)) => {
                tracing::warn!("Docker daemon health check failed: {error}");
                (false, "Docker daemon did not respond. Check its service and socket permissions.".to_string())
            }
            Err(_) => (false, "Docker daemon health check timed out after 3 seconds.".to_string()),
        };

        RuntimeStatus {
            mode: "docker",
            available,
            engine: "docker",
            message,
            can_manage_vpn: false,
        }
    }
}


/// Read-only Linux host probe for the official WireGuard / AmneziaWG tools.
/// It deliberately does not create interfaces or execute privileged commands.
#[derive(Debug, Default)]
pub struct HostRuntime;

fn executable_in_path(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else { return false };
    env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        let Ok(metadata) = fs::metadata(&candidate) else { return false };
        if !metadata.is_file() { return false; }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        { true }
    })
}

fn effective_caps_include_net_admin(status: &str) -> bool {
    status.lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|effective| effective & (1 << 12) != 0)
}

fn has_cap_net_admin() -> bool {
    fs::read_to_string("/proc/self/status")
        .map(|status| effective_caps_include_net_admin(&status))
        .unwrap_or(false)
}

fn has_tun_device() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        fs::metadata("/dev/net/tun")
            .map(|metadata| metadata.file_type().is_char_device())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    { false }
}

fn has_kernel_module(name: &str) -> bool {
    Path::new("/sys/module").join(name).is_dir()
}

#[async_trait]
impl RuntimeAdapter for HostRuntime {
    async fn status(&self) -> RuntimeStatus {
        #[cfg(not(target_os = "linux"))]
        {
            return RuntimeStatus {
                mode: "host",
                available: false,
                engine: "linux-host",
                message: "Host runtime preflight is supported only on Linux.".into(),
                can_manage_vpn: false,
            };
        }

        #[cfg(target_os = "linux")]
        {
            let ip = executable_in_path("ip");
            let awg_tool = executable_in_path("awg");
            let wg_tool = executable_in_path("wg");
            let awg_go = executable_in_path("amneziawg-go");
            let wg_go = executable_in_path("wireguard-go");
            let tun = has_tun_device();
            let net_admin = has_cap_net_admin();

            let awg_ready = ip && awg_tool && net_admin
                && (has_kernel_module("amneziawg") || (awg_go && tun));
            let wg_ready = ip && wg_tool && net_admin
                && (has_kernel_module("wireguard") || (wg_go && tun));

            let message = if awg_ready || wg_ready {
                format!(
                    "Read-only Linux preflight: AmneziaWG {}ready; WireGuard {}ready. No interface or peer has been created; runtime control is not enabled yet.",
                    if awg_ready { "" } else { "not " },
                    if wg_ready { "" } else { "not " },
                )
            } else {
                let mut missing = Vec::new();
                if !ip { missing.push("iproute2 (ip)"); }
                if !net_admin { missing.push("CAP_NET_ADMIN"); }
                if !tun && !has_kernel_module("amneziawg") && !has_kernel_module("wireguard") {
                    missing.push("/dev/net/tun or a loaded VPN kernel module");
                }
                if !awg_tool && !wg_tool { missing.push("awg and/or wg tools"); }
                if missing.is_empty() {
                    missing.push("matching VPN tool and kernel/userspace implementation");
                }
                format!("Linux host preflight incomplete. Missing: {}. This check is read-only.", missing.join(", "))
            };

            RuntimeStatus {
                mode: "host",
                available: awg_ready || wg_ready,
                engine: "linux-host",
                message,
                can_manage_vpn: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_caps_include_net_admin, HostRuntime, PreviewRuntime, RuntimeAdapter};

    #[tokio::test]
    async fn preview_runtime_never_claims_to_manage_vpn() {
        let status = PreviewRuntime.status().await;
        assert_eq!(status.mode, "preview");
        assert!(status.available);
        assert!(!status.can_manage_vpn);
        assert_eq!(status.engine, "none");
    }

    #[test]
    fn recognizes_cap_net_admin_bit_from_proc_status() {
        assert!(effective_caps_include_net_admin("Name:\ttest\nCapEff:\t0000000000001000\n"));
        assert!(!effective_caps_include_net_admin("CapEff:\t0000000000000800\n"));
        assert!(!effective_caps_include_net_admin("CapEff:\tnot-hex\n"));
        assert!(!effective_caps_include_net_admin("Name:\ttest\n"));
    }

    #[tokio::test]
    async fn host_preflight_never_claims_to_manage_vpn() {
        let status = HostRuntime.status().await;
        assert_eq!(status.mode, "host");
        assert_eq!(status.engine, "linux-host");
        assert!(!status.can_manage_vpn);
    }
}
