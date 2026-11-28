pub mod amnezia_uri;
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
use base64::Engine as _;
use bollard::Docker;
use serde::Serialize;
use tokio::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize)]
pub struct PeerRuntimeStat {
    pub public_key: String,
    pub allowed_ips: String,
    pub latest_handshake_unix: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

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

    async fn peer_stats(
        &self,
        _protocol: &str,
        _interface_name: &str,
    ) -> Result<Vec<PeerRuntimeStat>, &'static str> {
        Err("This runtime does not expose live peer statistics")
    }

    async fn interface_is_up(
        &self,
        _protocol: &str,
        _interface_name: &str,
    ) -> Result<bool, &'static str> {
        Err("This runtime cannot inspect Linux interfaces")
    }

    async fn remove_peer(
        &self,
        _protocol: &str,
        _interface_name: &str,
        _public_key: &str,
    ) -> Result<(), &'static str> {
        Err("This runtime does not support live peer removal")
    }

    async fn add_peer(
        &self,
        _protocol: &str,
        _interface_name: &str,
        _public_key: &str,
        _allowed_ip: &str,
        _preshared_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<(), &'static str> {
        Err("This runtime does not support live peer addition")
    }
}

/// Mark interrupted runtime operations as requiring administrator cleanup.
/// The next host-runtime stop is idempotent: it removes a partial interface if
/// present, or simply clears stale state when the interface is already gone.
pub async fn recover_interrupted_operations(
    pool: &sqlx::SqlitePool,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE runtime_operation IS NOT NULL OR status IN ('starting', 'stopping')"
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
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


fn validate_interface_name(interface_name: &str) -> Result<(), &'static str> {
    if interface_name.is_empty() || interface_name.len() > 15
        || !interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("Invalid generated VPN interface name");
    }
    Ok(())
}

fn validate_peer_public_key(public_key: &str) -> Result<(), &'static str> {
    if base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .map_or(true, |key| key.len() != 32)
    {
        return Err("Invalid WireGuard peer public key");
    }
    Ok(())
}

fn validate_peer_allowed_ip(allowed_ip: &str) -> Result<(), &'static str> {
    let address = allowed_ip.parse::<ipnet::Ipv4Net>()
        .map_err(|_| "Invalid WireGuard peer allowed IP")?;
    if address.prefix_len() != 32 {
        return Err("Live peer addition requires one host IPv4 address (/32)");
    }
    Ok(())
}

struct TemporarySecretFile {
    path: PathBuf,
}

impl Drop for TemporarySecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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
        let ip = trusted_executable_in_system_path("ip");
        let tun = has_tun_device();
        let net_admin = has_cap_net_admin() && has_effective_root();
        match protocol {
            "wireguard" => ip && net_admin
                && trusted_executable_in_system_path("wg") && trusted_executable_in_system_path("wg-quick")
                && (has_kernel_module("wireguard") || (trusted_executable_in_system_path("wireguard-go") && tun)),
            "amnezia-awg" => ip && net_admin
                && trusted_executable_in_system_path("awg") && trusted_executable_in_system_path("awg-quick")
                && (has_kernel_module("amneziawg") || (trusted_executable_in_system_path("amneziawg-go") && tun)),
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
        if !trusted_runtime_directory(&directory) {
            return Err("VPN config directory must be owned by the runtime user and have trusted, non-writable parent directories");
        }
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

    async fn interface_exists(&self, interface_name: &str) -> Result<bool, &'static str> {
        if interface_name.is_empty() || interface_name.len() > 15
            || !interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("Invalid generated VPN interface name");
        }
        let ip_binary = trusted_system_executable("ip")
            .ok_or("iproute2 binary is missing or not root-owned and protected")?;
        let mut command = Command::new(ip_binary);
        command
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .args(["link", "show", "dev"])
            .arg(interface_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(5), command.status()).await {
            Ok(Ok(status)) if status.success() => Ok(true),
            Ok(Ok(status)) if status.code() == Some(1) => Ok(false),
            Ok(Ok(_)) => Err("Could not reliably inspect the Linux VPN interface state"),
            Ok(Err(_)) => Err("Could not inspect the Linux VPN interface state"),
            Err(_) => Err("Timed out while inspecting the Linux VPN interface state"),
        }
    }

    async fn run_peer_dump(
        &self,
        protocol: &str,
        interface_name: &str,
    ) -> Result<Vec<PeerRuntimeStat>, &'static str> {
        if interface_name.is_empty() || interface_name.len() > 15
            || !interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("Invalid generated VPN interface name");
        }
        let binary = match protocol {
            "wireguard" => "wg",
            "amnezia-awg" => "awg",
            _ => return Err("Peer statistics support only WireGuard and AmneziaWG"),
        };
        if !Self::tools_ready(protocol) {
            return Err("Required Linux VPN tools, kernel support and CAP_NET_ADMIN are missing");
        }
        let binary_path = trusted_system_executable(binary)
            .ok_or("VPN control binary is missing or not root-owned and protected")?;
        let mut command = Command::new(binary_path);
        command
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .args(["show", interface_name, "dump"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn()
            .map_err(|_| "Could not execute VPN peer statistics command")?;
        let mut stdout = child.stdout.take()
            .ok_or("Could not capture VPN peer statistics output")?;
        let mut output = Zeroizing::new(Vec::new());
        let read_result = tokio::time::timeout(Duration::from_secs(10), async {
            use tokio::io::AsyncReadExt;
            (&mut stdout).take(1024 * 1024 + 1).read_to_end(&mut output).await
        }).await;
        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                let _ = child.kill().await;
                return Err("Could not read VPN peer statistics output");
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err("VPN peer statistics command timed out");
            }
        }
        if output.len() > 1024 * 1024 {
            let _ = child.kill().await;
            return Err("VPN peer statistics output exceeded the safety limit");
        }
        match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(_)) => return Err("Could not read live VPN peer statistics"),
            Ok(Err(_)) => return Err("Could not finish VPN peer statistics command"),
            Err(_) => {
                let _ = child.kill().await;
                return Err("VPN peer statistics command did not terminate");
            }
        }
        let dump = std::str::from_utf8(&output)
            .map_err(|_| "VPN peer statistics output is not valid UTF-8")?;
        parse_peer_dump(dump)
    }

    fn write_temporary_preshared_key(
        &self,
        interface_name: &str,
        secret: &[u8; 32],
    ) -> Result<TemporarySecretFile, &'static str> {
        let config_path = self.config_path(interface_name)?;
        let directory = config_path.parent()
            .ok_or("Could not resolve protected VPN config directory")?;
        let path = directory.join(format!(".{interface_name}-psk-{}.key", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)
            .map_err(|_| "Could not create protected temporary preshared-key file")?;
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(secret));
        if file.write_all(encoded.as_bytes()).is_err()
            || file.write_all(b"\n").is_err()
            || file.sync_all().is_err()
        {
            let _ = fs::remove_file(&path);
            return Err("Could not persist protected temporary preshared-key file");
        }
        Ok(TemporarySecretFile { path })
    }

    async fn add_peer_to_interface(
        &self,
        protocol: &str,
        interface_name: &str,
        public_key: &str,
        allowed_ip: &str,
        preshared_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<(), &'static str> {
        if !self.allow_mutations {
            return Err("Host mutations are disabled; set HOST_RUNTIME_ALLOW_MUTATIONS=true");
        }
        validate_interface_name(interface_name)?;
        validate_peer_public_key(public_key)?;
        validate_peer_allowed_ip(allowed_ip)?;
        let binary = match protocol {
            "wireguard" => "wg",
            "amnezia-awg" => "awg",
            _ => return Err("Live peer addition supports only WireGuard and AmneziaWG"),
        };
        if !Self::tools_ready(protocol) {
            return Err("Required Linux VPN tools, kernel support and CAP_NET_ADMIN are missing");
        }
        if !self.interface_exists(interface_name).await? {
            return Err("Managed VPN interface is not running");
        }
        let binary_path = trusted_system_executable(binary)
            .ok_or("VPN control binary is missing or not root-owned and protected")?;
        let mut command = Command::new(binary_path);
        command
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .args(["set", interface_name, "peer", public_key]);
        let _preshared_key_file = if let Some(secret) = preshared_key.as_deref() {
            let secret_file = self.write_temporary_preshared_key(interface_name, secret)?;
            command.args(["preshared-key"]).arg(&secret_file.path);
            Some(secret_file)
        } else {
            None
        };
        command
            .args(["allowed-ips", allowed_ip])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(10), command.status()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(_)) => Err("Could not install the new VPN peer; inspect host service logs"),
            Ok(Err(_)) => Err("Could not execute VPN peer installation command"),
            Err(_) => Err("VPN peer installation command timed out"),
        }
    }

    async fn remove_peer_from_interface(
        &self,
        protocol: &str,
        interface_name: &str,
        public_key: &str,
    ) -> Result<(), &'static str> {
        if !self.allow_mutations {
            return Err("Host mutations are disabled; set HOST_RUNTIME_ALLOW_MUTATIONS=true");
        }
        if interface_name.is_empty() || interface_name.len() > 15
            || !interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("Invalid generated VPN interface name");
        }
        if base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .map_or(true, |key| key.len() != 32)
        {
            return Err("Invalid WireGuard peer public key");
        }
        let binary = match protocol {
            "wireguard" => "wg",
            "amnezia-awg" => "awg",
            _ => return Err("Live peer removal supports only WireGuard and AmneziaWG"),
        };
        if !Self::tools_ready(protocol) {
            return Err("Required Linux VPN tools, kernel support and CAP_NET_ADMIN are missing");
        }
        if !self.interface_exists(interface_name).await? {
            // The interface is already absent, so there is no live peer to retain.
            return Ok(());
        }
        let binary_path = trusted_system_executable(binary)
            .ok_or("VPN control binary is missing or not root-owned and protected")?;
        let mut command = Command::new(binary_path);
        command
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .args(["set", interface_name, "peer", public_key, "remove"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(10), command.status()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(_)) => Err("Could not revoke the expired VPN peer; inspect host service logs"),
            Ok(Err(_)) => Err("Could not execute VPN peer removal command"),
            Err(_) => Err("VPN peer removal command timed out"),
        }
    }

    async fn run_quick(
        &self,
        binary: &'static str,
        action: &'static str,
        path: &Path,
    ) -> Result<(), &'static str> {
        let binary_path = trusted_system_executable(binary)
            .ok_or("VPN quick binary is missing or not root-owned and protected")?;
        let mut command = Command::new(binary_path);
        command
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .arg(action)
            .arg(path)
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


/// Parse the stable wg/awg "show <interface> dump" tab-separated format.
/// The interface's private/preshared keys and peer endpoint are intentionally discarded.
fn parse_peer_dump(dump: &str) -> Result<Vec<PeerRuntimeStat>, &'static str> {
    let mut lines = dump.lines();
    let interface_line = lines.next().ok_or("VPN peer dump is empty")?;
    if interface_line.split('\t').count() != 4 {
        return Err("VPN peer dump has an invalid interface header");
    }

    let mut peers = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 8 {
            return Err("VPN peer dump contains a malformed peer row");
        }
        if base64::engine::general_purpose::STANDARD
            .decode(fields[0])
            .map_or(true, |key| key.len() != 32)
        {
            return Err("VPN peer dump contains an invalid public key");
        }
        if !seen_keys.insert(fields[0]) {
            return Err("VPN peer dump contains a duplicate peer public key");
        }
        let allowed_ips = fields[3];
        let latest_handshake = fields[4].parse::<u64>()
            .map_err(|_| "VPN peer dump contains an invalid handshake timestamp")?;
        let rx_bytes = fields[5].parse::<u64>()
            .map_err(|_| "VPN peer dump contains an invalid receive counter")?;
        let tx_bytes = fields[6].parse::<u64>()
            .map_err(|_| "VPN peer dump contains an invalid transmit counter")?;
        peers.push(PeerRuntimeStat {
            public_key: fields[0].to_string(),
            allowed_ips: allowed_ips.to_string(),
            latest_handshake_unix: (latest_handshake != 0).then_some(latest_handshake),
            rx_bytes,
            tx_bytes,
        });
    }
    Ok(peers)
}

fn trusted_executable_in_system_path(name: &str) -> bool {
    trusted_system_executable(name).is_some()
}

/// Resolve binaries only from standard system directories. Refuse binaries or
/// parent directories that are not root-owned or are group/world writable.
fn trusted_system_executable(name: &str) -> Option<PathBuf> {
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return None;
    }
    const DIRECTORIES: [&str; 6] = [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ];
    for directory in DIRECTORIES {
        let Ok(candidate) = fs::canonicalize(Path::new(directory).join(name)) else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.permissions().mode() & 0o111 == 0
            {
                continue;
            }
            let mut parent = candidate.parent()?;
            let trusted_root = if candidate.starts_with("/usr") {
                Path::new("/usr")
            } else if candidate.starts_with("/bin") {
                Path::new("/bin")
            } else if candidate.starts_with("/sbin") {
                Path::new("/sbin")
            } else {
                continue;
            };
            let mut safe = true;
            loop {
                let parent_meta = fs::metadata(parent).ok()?;
                if parent_meta.uid() != 0 || parent_meta.permissions().mode() & 0o022 != 0 {
                    safe = false;
                    break;
                }
                if parent == trusted_root {
                    break;
                }
                let Some(next) = parent.parent() else {
                    safe = false;
                    break;
                };
                parent = next;
            }
            if safe {
                return Some(candidate);
            }
        }
        #[cfg(not(unix))]
        {
            return Some(candidate);
        }
    }
    None
}

fn effective_uid(status: &str) -> Option<u32> {
    status.lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_ascii_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
}

fn effective_uid_is_root(status: &str) -> bool {
    effective_uid(status) == Some(0)
}

fn current_effective_uid() -> Option<u32> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| effective_uid(&status))
}

/// Require the final runtime directory to belong to this process and be private.
/// Parent directories may be owned by root or this user, but cannot be writable
/// by group/other; root-owned sticky directories (for example /tmp) are allowed.
fn trusted_runtime_directory(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Some(uid) = current_effective_uid() else { return false; };
        let Ok(final_meta) = fs::metadata(path) else { return false; };
        if final_meta.uid() != uid || final_meta.permissions().mode() & 0o077 != 0 {
            return false;
        }
        let mut current = path;
        loop {
            let Ok(metadata) = fs::metadata(current) else { return false; };
            let mode = metadata.permissions().mode();
            let owned_by_trusted_user = metadata.uid() == 0 || metadata.uid() == uid;
            let writable_by_untrusted = mode & 0o022 != 0
                && !(metadata.uid() == 0 && mode & 0o1000 != 0);
            if !owned_by_trusted_user || writable_by_untrusted {
                return false;
            }
            if current == Path::new("/") {
                break;
            }
            let Some(parent) = current.parent() else { return false; };
            current = parent;
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn has_effective_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .map(|status| effective_uid_is_root(&status))
        .unwrap_or(false)
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
            let awg_ready = Self::tools_ready("amnezia-awg");
            let wg_ready = Self::tools_ready("wireguard");
            let available = awg_ready || wg_ready;
            let can_manage = available && self.allow_mutations;
            let message = if can_manage {
                format!(
                    "Linux host runtime enabled. AmneziaWG {}; WireGuard {}. Interface operations are enabled by HOST_RUNTIME_ALLOW_MUTATIONS.",
                    if awg_ready { "ready" } else { "not ready" },
                    if wg_ready { "ready" } else { "not ready" },
                )
            } else if available {
                "Linux VPN tools are ready, but interface changes are disabled. Set HOST_RUNTIME_ALLOW_MUTATIONS=true to enable them.".to_string()
            } else {
                let mut missing = Vec::new();
                if !trusted_executable_in_system_path("ip") { missing.push("iproute2 (ip)"); }
                if !has_effective_root() { missing.push("effective UID 0 (root)"); }
                if !has_cap_net_admin() { missing.push("CAP_NET_ADMIN"); }
                if !has_tun_device() && !has_kernel_module("amneziawg") && !has_kernel_module("wireguard") {
                    missing.push("/dev/net/tun or a loaded VPN kernel module");
                }
                if !trusted_executable_in_system_path("awg") || !trusted_executable_in_system_path("awg-quick") {
                    missing.push("AmneziaWG awg and awg-quick");
                }
                if !trusted_executable_in_system_path("wg") || !trusted_executable_in_system_path("wg-quick") {
                    missing.push("WireGuard wg and wg-quick");
                }
                format!("Linux host preflight incomplete: {}.", missing.join(", "))
            };

            RuntimeStatus {
                mode: "host",
                available,
                engine: "linux-host",
                message,
                can_manage_vpn: can_manage,
            }
        }
    }

    async fn start_interface(
        &self,
        protocol: &str,
        interface_name: &str,
        config: Zeroizing<String>,
    ) -> Result<(), &'static str> {
        if !self.allow_mutations {
            return Err("Host mutations are disabled; set HOST_RUNTIME_ALLOW_MUTATIONS=true");
        }
        let binary = Self::quick_binary(protocol)?;
        if !Self::tools_ready(protocol) {
            return Err("Required Linux VPN tools, kernel support and CAP_NET_ADMIN are missing");
        }
        let path = self.config_path(interface_name)?;
        self.write_config_file(&path, config.as_bytes())?;
        if let Err(error) = self.run_quick(binary, "up", &path).await {
            // A failed up can leave a partially created interface; try rollback
            // while the protected config is still present.
            let _ = self.run_quick(binary, "down", &path).await;
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(())
    }

    async fn stop_interface(
        &self,
        protocol: &str,
        interface_name: &str,
    ) -> Result<(), &'static str> {
        if !self.allow_mutations {
            return Err("Host mutations are disabled; set HOST_RUNTIME_ALLOW_MUTATIONS=true");
        }
        let binary = Self::quick_binary(protocol)?;
        if !Self::tools_ready(protocol) {
            return Err("Required Linux VPN tools, kernel support and CAP_NET_ADMIN are missing");
        }
        let path = self.config_path(interface_name)?;
        let interface_exists = self.interface_exists(interface_name).await?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !interface_exists => {
                // Recover a stale DB "running/error" state after a crash when
                // both the interface and its private config have disappeared.
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("Managed VPN interface exists but its protected config file is missing");
            }
            Err(_) => return Err("Could not inspect managed VPN config file"),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("Managed VPN config path is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if Some(metadata.uid()) != current_effective_uid()
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err("Managed VPN config file ownership, permissions or link count are unsafe");
            }
        }
        if interface_exists {
            self.run_quick(binary, "down", &path).await?;
        }
        fs::remove_file(path)
            .map_err(|_| "Interface is stopped or absent, but protected config cleanup failed")?;
        Ok(())
    }


    async fn peer_stats(
        &self,
        protocol: &str,
        interface_name: &str,
    ) -> Result<Vec<PeerRuntimeStat>, &'static str> {
        self.run_peer_dump(protocol, interface_name).await
    }

    async fn interface_is_up(
        &self,
        protocol: &str,
        interface_name: &str,
    ) -> Result<bool, &'static str> {
        Self::quick_binary(protocol)?;
        self.interface_exists(interface_name).await
    }

    async fn remove_peer(
        &self,
        protocol: &str,
        interface_name: &str,
        public_key: &str,
    ) -> Result<(), &'static str> {
        self.remove_peer_from_interface(protocol, interface_name, public_key).await
    }

    async fn add_peer(
        &self,
        protocol: &str,
        interface_name: &str,
        public_key: &str,
        allowed_ip: &str,
        preshared_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<(), &'static str> {
        self.add_peer_to_interface(protocol, interface_name, public_key, allowed_ip, preshared_key).await
    }
}

pub fn interface_name_for_profile(protocol: &str, profile_id: &str) -> Result<String, &'static str> {
    let prefix = match protocol {
        "wireguard" => "wg",
        "amnezia-awg" => "awg",
        _ => return Err("Unsupported interface protocol"),
    };
    let compact: String = profile_id.bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .map(char::from)
        .take(10)
        .collect();
    if compact.len() != 10 {
        return Err("Profile ID must contain at least 10 hexadecimal characters");
    }
    Ok(format!("{prefix}{compact}"))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use super::{
        effective_caps_include_net_admin, effective_uid_is_root, interface_name_for_profile,
        recover_interrupted_operations, HostRuntime, PreviewRuntime, RuntimeAdapter,
    };
    use std::{fs, path::PathBuf};
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn preview_runtime_never_claims_to_manage_vpn() {
        let status = PreviewRuntime.status().await;
        assert_eq!(status.mode, "preview");
        assert!(status.available);
        assert!(!status.can_manage_vpn);
        assert_eq!(status.engine, "none");
    }

    #[test]
    fn recognizes_effective_root_uid_from_proc_status() {
        assert!(effective_uid_is_root("Uid:\t0\t0\t0\t0\n"));
        assert!(!effective_uid_is_root("Uid:\t1000\t1000\t1000\t1000\n"));
        assert!(!effective_uid_is_root("Uid:\t0\t1000\t0\t0\n"));
        assert!(!effective_uid_is_root("Name:\ttest\n"));
    }

    #[test]
    fn recognizes_cap_net_admin_bit_from_proc_status() {
        assert!(effective_caps_include_net_admin("Name:\ttest\nCapEff:\t0000000000001000\n"));
        assert!(!effective_caps_include_net_admin("CapEff:\t0000000000000800\n"));
        assert!(!effective_caps_include_net_admin("CapEff:\tnot-hex\n"));
        assert!(!effective_caps_include_net_admin("Name:\ttest\n"));
    }

    #[tokio::test]
    async fn startup_recovery_clears_interrupted_runtime_operations() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE protocol_containers (id TEXT PRIMARY KEY, status TEXT NOT NULL, runtime_operation TEXT)"
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO protocol_containers (id, status, runtime_operation) VALUES
             ('start-crash', 'stopped', 'start'),
             ('stop-crash', 'running', 'stop'),
             ('legacy-start-crash', 'starting', NULL),
             ('healthy', 'running', NULL)"
        ).execute(&pool).await.unwrap();

        assert_eq!(recover_interrupted_operations(&pool).await.unwrap(), 3);

        let healthy = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT status, runtime_operation FROM protocol_containers WHERE id = 'healthy'"
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(healthy, ("running".into(), None));

        for id in ["start-crash", "stop-crash", "legacy-start-crash"] {
            let recovered = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT status, runtime_operation FROM protocol_containers WHERE id = ?"
            ).bind(id).fetch_one(&pool).await.unwrap();
            assert_eq!(recovered, ("error".into(), None), "recovery failed for {id}");
        }

        // Recovery is idempotent and does not change healthy running profiles.
        assert_eq!(recover_interrupted_operations(&pool).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn host_preflight_never_claims_to_manage_vpn() {
        let status = HostRuntime::new().status().await;
        assert_eq!(status.mode, "host");
        assert_eq!(status.engine, "linux-host");
        assert!(!status.can_manage_vpn);
    }

    #[test]
    fn runtime_config_files_are_private_and_interface_names_are_confined() {
        let directory = std::env::temp_dir()
            .join(format!("amnezia-panel-test-{}", uuid::Uuid::new_v4()));
        let runtime = HostRuntime {
            config_dir: PathBuf::from(&directory),
            allow_mutations: false,
        };
        let path = runtime.config_path("wgabcdef1234").unwrap();
        assert!(path.starts_with(&directory));
        assert!(runtime.config_path("../../etc/passwd").is_err());
        runtime.write_config_file(&path, b"[Interface]\n").unwrap();
        assert!(runtime.write_config_file(&path, b"overwrite").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory_mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temporary_preshared_key_files_are_private_and_removed_after_use() {
        let directory = std::env::temp_dir()
            .join(format!("amnezia-panel-psk-test-{}", uuid::Uuid::new_v4()));
        let runtime = HostRuntime {
            config_dir: PathBuf::from(&directory),
            allow_mutations: true,
        };
        let secret = [0x5a_u8; 32];
        let file = runtime.write_temporary_preshared_key("awgabcdef1234", &secret).unwrap();
        let path = file.path.clone();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            format!("{}\n", base64::engine::general_purpose::STANDARD.encode(secret))
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
        }

        drop(file);
        assert!(!path.exists(), "temporary preshared key file was not removed");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_runtime_config_directories() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir()
            .join(format!("amnezia-panel-symlink-test-{}", uuid::Uuid::new_v4()));
        let real = base.join("real");
        let link = base.join("link");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();
        let runtime = HostRuntime {
            config_dir: link,
            allow_mutations: false,
        };
        assert!(runtime.config_path("wgabcdef1234").is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn parses_peer_dump_without_exposing_secret_columns() {
        let public = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let dump = format!(
            "private-public-key\tserver-public-key\t51820\t0\n{public}\tnone\t198.51.100.10:12345\t10.66.0.2/32\t1700000000\t1024\t2048\t25\n"
        );
        let stats = super::parse_peer_dump(&dump).unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].public_key, public);
        assert_eq!(stats[0].latest_handshake_unix, Some(1_700_000_000));
        assert_eq!(stats[0].rx_bytes, 1024);
        assert_eq!(stats[0].tx_bytes, 2048);
        assert_eq!(stats[0].allowed_ips, "10.66.0.2/32");
        assert!(!format!("{:?}", stats[0]).contains("198.51.100.10"));
        assert!(!format!("{:?}", stats[0]).contains("private-public-key"));
    }

    #[test]
    fn rejects_malformed_peer_dump_rows() {
        assert!(super::parse_peer_dump("").is_err());
        assert!(super::parse_peer_dump("header\tpublic\tport\tfwmark\nshort\trow\n").is_err());

        let public = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let duplicate = format!(
            "private\tpublic\t51820\t0\n{public}\tnone\t(none)\t10.66.0.2/32\t0\t0\t0\toff\n{public}\tnone\t(none)\t10.66.0.3/32\t0\t0\t0\toff\n"
        );
        assert!(super::parse_peer_dump(&duplicate).is_err());
    }

    #[test]
    fn live_peer_inputs_reject_command_injection_and_non_host_routes() {
        use super::{
            validate_interface_name, validate_peer_allowed_ip, validate_peer_public_key,
        };
        use base64::Engine as _;

        for invalid in ["", "a;touch", "wg test", "../wg0", "interface-name-too-long", "wg0\n"] {
            assert!(validate_interface_name(invalid).is_err(), "accepted interface {invalid:?}");
        }
        for valid in ["wg0123456789", "awg_abc-123"] {
            assert!(validate_interface_name(valid).is_ok());
        }

        let valid_key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        assert!(validate_peer_public_key(&valid_key).is_ok());
        for invalid in ["", "not-a-key", "YQ==", "a;echo pwned"] {
            assert!(validate_peer_public_key(invalid).is_err(), "accepted key {invalid:?}");
        }

        assert!(validate_peer_allowed_ip("10.66.0.2/32").is_ok());
        assert!(validate_peer_allowed_ip("10.66.0.0/24").is_err());
        assert!(validate_peer_allowed_ip("0.0.0.0/0").is_err());
        assert!(validate_peer_allowed_ip("::1/128").is_err());
        assert!(validate_peer_allowed_ip("10.66.0.2/32;id").is_err());
    }

    #[test]
    fn creates_stable_linux_interface_names_from_profile_ids() {
        assert_eq!(
            interface_name_for_profile("amnezia-awg", "12345678-1234-1234-1234-123456789abc").unwrap(),
            "awg1234567812"
        );
        assert_eq!(
            interface_name_for_profile("wireguard", "abcdef12-3456-7890-abcd-ef1234567890").unwrap(),
            "wgabcdef1234"
        );
        assert!(interface_name_for_profile("openvpn", "1234567890").is_err());
        assert!(interface_name_for_profile("wireguard", "short").is_err());
    }
}
