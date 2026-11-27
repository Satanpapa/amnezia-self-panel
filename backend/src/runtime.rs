use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub mode: &'static str,
    pub available: bool,
    pub engine: &'static str,
    pub message: &'static str,
    pub can_manage_vpn: bool,
}

/// Boundary between the HTTP/API layer and the process/container runtime.
/// Implementations must never execute user-provided shell fragments.
pub trait RuntimeAdapter: Send + Sync {
    fn status(&self) -> RuntimeStatus;
}

/// Safe local adapter used until a Docker Engine adapter is configured.
/// It deliberately reports that it cannot start or manage VPN services.
#[derive(Debug, Default)]
pub struct PreviewRuntime;

impl RuntimeAdapter for PreviewRuntime {
    fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            mode: "preview",
            available: true,
            engine: "none",
            message: "Preview mode: metadata is stored in SQLite; no VPN process or container is running.",
            can_manage_vpn: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PreviewRuntime, RuntimeAdapter};

    #[test]
    fn preview_runtime_never_claims_to_manage_vpn() {
        let status = PreviewRuntime.status();
        assert_eq!(status.mode, "preview");
        assert!(status.available);
        assert!(!status.can_manage_vpn);
        assert_eq!(status.engine, "none");
    }
}
