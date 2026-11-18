use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineKind {
    SingBox,
    XrayCore,
    Mihomo,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineDescriptor {
    pub kind: EngineKind,
    pub binary_name: &'static str,
    pub integration_stage: &'static str,
}

pub const ENGINE_TARGETS: [EngineDescriptor; 3] = [
    EngineDescriptor {
        kind: EngineKind::SingBox,
        binary_name: "sing-box",
        integration_stage: "planned",
    },
    EngineDescriptor {
        kind: EngineKind::XrayCore,
        binary_name: "xray",
        integration_stage: "planned",
    },
    EngineDescriptor {
        kind: EngineKind::Mihomo,
        binary_name: "mihomo",
        integration_stage: "planned",
    },
];
