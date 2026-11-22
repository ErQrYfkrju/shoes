//! Structured, non-starting configuration validation for mobile consumers.

use serde::{Serialize, de::IntoDeserializer};
use std::collections::HashSet;

use crate::config::{Config, ResolvedConfig, ResolvedServerProxyConfig};

pub const MAX_DIAGNOSTICS: usize = 16;
pub const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Proxy,
    Vpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    EmptyConfig,
    YamlSyntax,
    ConfigSchema,
    ConfigSemantic,
    ModeIncompatible,
    LocalIo,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationDiagnostic {
    pub code: DiagnosticCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl ValidationDiagnostic {
    pub fn new(
        code: DiagnosticCode,
        message: impl Into<String>,
        entry: Option<usize>,
        path: Option<String>,
        line: Option<u32>,
        column: Option<u32>,
    ) -> Self {
        Self {
            code,
            message: bounded_message(message.into()),
            entry,
            path,
            line,
            column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub schema_version: u16,
    pub valid: bool,
    pub diagnostics: Vec<ValidationDiagnostic>,
}

impl ValidationReport {
    pub fn valid() -> Self {
        Self {
            schema_version: 1,
            valid: true,
            diagnostics: Vec::new(),
        }
    }

    pub fn from_diagnostics(mut diagnostics: Vec<ValidationDiagnostic>) -> Self {
        diagnostics.truncate(MAX_DIAGNOSTICS);
        if diagnostics.is_empty() {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::Internal,
                "Configuration validation failed without a diagnostic",
                None,
                None,
                None,
                None,
            ));
        }
        Self {
            schema_version: 1,
            valid: false,
            diagnostics,
        }
    }
}

pub async fn validate_config(config_yaml: &str, mode: ValidationMode) -> ValidationReport {
    if config_yaml.trim().is_empty() {
        return ValidationReport::from_diagnostics(vec![ValidationDiagnostic::new(
            DiagnosticCode::EmptyConfig,
            "Configuration is empty",
            None,
            None,
            None,
            None,
        )]);
    }

    let values = match serde_yaml::from_str::<Vec<serde_yaml::Value>>(config_yaml) {
        Ok(values) if values.is_empty() => {
            return ValidationReport::from_diagnostics(vec![ValidationDiagnostic::new(
                DiagnosticCode::EmptyConfig,
                "Configuration contains no entries",
                None,
                None,
                None,
                None,
            )]);
        }
        Ok(values) => values,
        Err(error) => {
            let (line, column) = error_location(&error);
            return ValidationReport::from_diagnostics(vec![ValidationDiagnostic::new(
                DiagnosticCode::YamlSyntax,
                "Invalid YAML syntax",
                None,
                None,
                line,
                column,
            )]);
        }
    };

    let sensitive_values = SensitiveValues::from_yaml(&values);
    for (index, value) in values.iter().enumerate() {
        let result: Result<Config, _> =
            serde_path_to_error::deserialize(value.clone().into_deserializer());
        if let Err(error) = result {
            let path = error.path().to_string();
            let inner = error.into_inner();
            let (line, column) = error_location(&inner);
            let raw_message = inner.to_string();
            let path = if path.is_empty() || path == "." {
                unknown_field_path(value, &raw_message)
            } else {
                Some(path)
            };
            let message = sensitive_values.redact(&raw_message);
            return ValidationReport::from_diagnostics(vec![ValidationDiagnostic::new(
                DiagnosticCode::ConfigSchema,
                message,
                Some(index),
                path,
                line,
                column,
            )]);
        }
    }

    match super::common::compile_ffi_config(config_yaml).await {
        Ok(validated) => {
            if let Err(diagnostic) = validate_mode(&validated, mode, &sensitive_values) {
                ValidationReport::from_diagnostics(vec![diagnostic])
            } else {
                ValidationReport::valid()
            }
        }
        Err(error) => {
            let code = match error.kind() {
                std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::UnexpectedEof => DiagnosticCode::LocalIo,
                _ => DiagnosticCode::ConfigSemantic,
            };
            let message = sensitive_values.redact(&error.to_string());
            ValidationReport::from_diagnostics(vec![ValidationDiagnostic::new(
                code, message, None, None, None, None,
            )])
        }
    }
}

fn validate_mode(
    validated: &crate::config::ValidatedConfigs,
    mode: ValidationMode,
    sensitive_values: &SensitiveValues,
) -> Result<(), ValidationDiagnostic> {
    let incompatible = |message: String| {
        ValidationDiagnostic::new(
            DiagnosticCode::ModeIncompatible,
            sensitive_values.redact(&message),
            None,
            None,
            None,
            None,
        )
    };
    match mode {
        ValidationMode::Proxy => {
            if validated
                .configs
                .iter()
                .any(|config| matches!(config, ResolvedConfig::TunServer(_)))
            {
                return Err(incompatible(
                    "Proxy mode does not accept TUN configs".into(),
                ));
            }
            if validated.configs.iter().any(|config| {
                matches!(
                    config,
                    ResolvedConfig::Server(server)
                        if matches!(server.protocol, ResolvedServerProxyConfig::Wireguard(_))
                )
            }) {
                return Err(incompatible(
                    "WireGuard requires the process runtime and is not supported by Proxy mode"
                        .into(),
                ));
            }
            if validated.configs.is_empty() {
                return Err(incompatible("No server configs found in YAML".into()));
            }
        }
        ValidationMode::Vpn => {
            let has_android_tun = validated.configs.iter().any(|config| {
                matches!(
                    config,
                    ResolvedConfig::TunServer(tun) if tun.device_fd.is_some()
                )
            });
            if !has_android_tun {
                return Err(incompatible(
                    "VPN mode requires a TUN config with device_fd (use -1 as the Android placeholder)"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

fn error_location(error: &serde_yaml::Error) -> (Option<u32>, Option<u32>) {
    error.location().map_or((None, None), |location| {
        (Some(location.line() as u32), Some(location.column() as u32))
    })
}

fn unknown_field_path(value: &serde_yaml::Value, message: &str) -> Option<String> {
    let field = message.split("unknown field `").nth(1)?.split('`').next()?;
    find_field_path(value, field)
}

fn find_field_path(value: &serde_yaml::Value, field: &str) -> Option<String> {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, item) in mapping {
                let key = key.as_str()?;
                if key == field {
                    return Some(key.to_owned());
                }
                if let Some(child) = find_field_path(item, field) {
                    return Some(format!("{key}.{child}"));
                }
            }
            None
        }
        serde_yaml::Value::Sequence(sequence) => {
            for (index, item) in sequence.iter().enumerate() {
                if let Some(child) = find_field_path(item, field) {
                    return Some(format!("[{index}].{child}"));
                }
            }
            None
        }
        _ => None,
    }
}

fn bounded_message(mut message: String) -> String {
    if message.len() <= MAX_DIAGNOSTIC_MESSAGE_BYTES {
        return message;
    }
    let mut boundary = MAX_DIAGNOSTIC_MESSAGE_BYTES.saturating_sub(3);
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message.push_str("...");
    message
}

struct SensitiveValues {
    values: Vec<String>,
}

impl SensitiveValues {
    fn from_yaml(values: &[serde_yaml::Value]) -> Self {
        let mut collected = HashSet::new();
        for value in values {
            collect_scalar_values(value, None, &mut collected);
        }
        let mut values: Vec<_> = collected.into_iter().collect();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { values }
    }

    fn redact(&self, message: &str) -> String {
        let mut redacted = message.to_owned();
        for value in &self.values {
            if !value.is_empty() {
                redacted = redacted.replace(value, "[redacted]");
            }
        }
        if redacted.trim().is_empty() {
            "Configuration validation failed".into()
        } else {
            redacted
        }
    }
}

fn collect_scalar_values(
    value: &serde_yaml::Value,
    key: Option<&str>,
    collected: &mut HashSet<String>,
) {
    match value {
        serde_yaml::Value::String(text) => {
            if text.len() >= 4 || key.is_some_and(is_sensitive_key) {
                collected.insert(text.clone());
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for item in sequence {
                collect_scalar_values(item, key, collected);
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            for (key_value, item) in mapping {
                let item_key = key_value.as_str();
                collect_scalar_values(item, item_key, collected);
            }
        }
        _ => {}
    }
}

pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "password"
        || key.ends_with("_password")
        || key == "private_key"
        || key == "pre_shared_key"
        || key == "secret"
        || key == "encryption"
        || key == "decryption"
        || key == "user_id"
        || key == "username"
        || key == "key"
        || key.contains("token")
}
