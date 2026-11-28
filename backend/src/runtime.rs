pub mod awg_config;

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use async_trait::async_trait;
use bollard::Docker;
use serde::Serialize;
use tokio::process::Command;
use zeroize::Zeroizing;

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

    async fn start_interface(
        &self,
        _protocol: &str,
        _interface_name: &str,
        _config: Zeroizing<String>,
    ) -> Result<(), &'static str> {
        Err("This runtime does not support VPN interface management")
    }

    async fn stop_interface(
        &self,
        _protocol: &str,
        _interface_name: &str,
    ) -> Result<(), &'static str> {
        Err("This runtime does not support VPN interface management")
    }
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


/// Linux host runtime. Mutating operations require an explicit environment opt-in.
pub struct HostRuntime {
    config_dir: PathBuf,
    allow_mutations: bool,
}

impl Default for HostRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl HostRuntime {
    pub fn new() -> Self {
        let config_dir = env::var_os("HOST_RUNTIME_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/amnezia-panel/interfaces"));
        let allow_mutations = env::var("HOST_RUNTIME_ALLOW_MUTATIONS")
            .map(|value| value.trim() == "true")
            .unwrap_or(false);
        Self { config_dir, allow_mutations }
    }

    fn quick_binary(protocol: &str) -> Result<&'static str, &'static str> {
        match protocol {
            "wireguard" => Ok("wg-quick"),
            "amnezia-awg" => Ok("awg-quick"),
            _ => Err("Host runtime supports only WireGuard and AmneziaWG"),
        }
    }

    fn tools_ready(protocol: &str) -> bool {
        let ip = executable_in_path("ip");
        let tun = has_tun_device();
        let net_admin = has_cap_net_admin();
        match protocol {
            "wireguard" => ip && net_admin
                && executable_in_path("wg") && executable_in_path("wg-quick")
                && (has_kernel_module("wireguard") || (executable_in_path("wireguard-go") && tun)),
            "amnezia-awg" => ip && net_admin
                && executable_in_path("awg") && executable_in_path("awg-quick")
                && (has_kernel_module("amneziawg") || (executable_in_path("amneziawg-go") && tun)),
            _ => false,
        }
    }

    fn config_path(&self, interface_name: &str) -> Result<PathBuf, &'static str> {
        if interface_name.is_empty() || interface_name.len() > 15
            || !interface_name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("Invalid generated VPN interface name");
        }
        fs::create_dir_all(&self.config_dir)
            .map_err(|_| "Could not create protected VPN config directory")?;
        let metadata = fs::symlink_metadata(&self.config_dir)
            .map_err(|_| "Could not inspect VPN config directory")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("VPN config path must be a real directory, not a symlink");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.config_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| "Could not restrict VPN config directory permissions")?;
        }
        let directory = fs::canonicalize(&self.config_dir)
            .map_err(|_| "Could not resolve VPN config directory")?;
        Ok(directory.join(format!("{interface_name}.conf")))
    }

    fn write_config_file(&self, path: &Path, config: &[u8]) -> Result<(), &'static str> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)
            .map_err(|_| "VPN config already exists or cannot be created safely")?;
        if file.write_all(config).is_err() || file.sync_all().is_err() {
            let _ = fs::remove_file(path);
            return Err("Could not persist protected VPN config");
        }
        Ok(())
    }

    async fn run_quick(
        &self,
        binary: &'static str,
        action: &'static str,
        path: &Path,
    ) -> Result<(), &'static str> {
        let mut command = Command::new(binary);
        command.arg(action).arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(45), command.status()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(_)) => Err("VPN quick command failed; inspect host service logs"),
            Ok(Err(_)) => Err("Could not execute VPN quick command"),
            Err(_) => Err("VPN quick command timed out and was terminated"),
        }
    }
}

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
