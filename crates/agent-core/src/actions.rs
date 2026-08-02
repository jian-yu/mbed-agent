//! Bounded, declarative user and vendor action manifests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::config::ExtensionsConfig;

pub const ACTION_MANIFEST_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Error)]
pub enum ActionRegistryError {
    #[error("action directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("action manifest is unsafe: {0}")]
    UnsafeManifest(PathBuf),
    #[error("action manifest I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("action manifest is invalid: {0}")]
    Invalid(String),
    #[error("action registry exceeds its configured capacity")]
    Capacity,
    #[error("action id is duplicated: {0}")]
    Duplicate(String),
    #[error("action is unavailable on this platform")]
    PlatformUnavailable,
    #[error("action inputs are invalid: {0}")]
    InvalidInputs(String),
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionMode {
    #[default]
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionManifest {
    pub schema_version: u16,
    pub actions: Vec<ActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub mode: ActionMode,
    #[serde(default)]
    pub llm_enabled: bool,
    pub platforms: Vec<String>,
    pub executable: PathBuf,
    #[serde(default)]
    pub argv: Vec<ActionArgSpec>,
    #[serde(default)]
    pub inputs: BTreeMap<String, ActionInputSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionArgSpec {
    Literal { value: String },
    Input { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionInputSpec {
    String {
        max_bytes: usize,
        #[serde(default)]
        allowed_values: Vec<String>,
        #[serde(default)]
        allow_leading_dash: bool,
    },
    Integer {
        min: i64,
        max: i64,
    },
    Boolean {
        true_value: String,
        false_value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionInvocation {
    pub executable: PathBuf,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ActionRegistry {
    actions: BTreeMap<String, ActionSpec>,
}

impl ActionRegistry {
    /// Loads every direct `.toml` manifest from configured directories.
    ///
    /// Missing directories are ignored. Existing directories and manifests must have the trusted
    /// owner and must not be symlinks or writable by group/other. Duplicate IDs and any malformed
    /// manifest fail the whole load.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, malformed manifests, duplicates, or capacity overflow.
    pub fn load(config: &ExtensionsConfig) -> Result<Self, ActionRegistryError> {
        if !config.enabled {
            return Ok(Self::default());
        }
        let mut manifests = Vec::new();
        for directory in &config.directories {
            collect_manifests(directory, config, &mut manifests)?;
        }
        manifests.sort();
        if manifests.len() > config.max_manifests {
            return Err(ActionRegistryError::Capacity);
        }

        let mut actions = BTreeMap::new();
        for path in manifests {
            let encoded = read_manifest(&path, config.max_manifest_bytes)?;
            let manifest: ActionManifest = toml::from_str(&encoded)
                .map_err(|error| ActionRegistryError::Invalid(error.to_string()))?;
            if manifest.schema_version != ACTION_MANIFEST_SCHEMA_VERSION {
                return Err(ActionRegistryError::Invalid(format!(
                    "{} uses unsupported schema_version {}",
                    path.display(),
                    manifest.schema_version
                )));
            }
            for action in manifest.actions {
                validate_action(&action, config)?;
                let id = action.id.clone();
                if actions.insert(id.clone(), action).is_some() {
                    return Err(ActionRegistryError::Duplicate(id));
                }
                if actions.len() > config.max_actions {
                    return Err(ActionRegistryError::Capacity);
                }
            }
        }
        Ok(Self { actions })
    }

    #[must_use]
    pub fn available(&self, platform: &str) -> Vec<&ActionSpec> {
        self.actions
            .values()
            .filter(|action| action_supports_platform(action, platform))
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    #[must_use]
    pub fn get(&self, id: &str, platform: &str) -> Option<&ActionSpec> {
        self.actions
            .get(id)
            .filter(|action| action_supports_platform(action, platform))
    }

    /// Expands validated JSON inputs into an exact executable and argv vector.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown action/platform, missing or extra inputs, type mismatches,
    /// or configured bounds violations.
    pub fn invocation(
        &self,
        id: &str,
        platform: &str,
        inputs: &Value,
        config: &ExtensionsConfig,
    ) -> Result<ActionInvocation, ActionRegistryError> {
        let action = self
            .actions
            .get(id)
            .ok_or_else(|| ActionRegistryError::InvalidInputs("unknown action id".into()))?;
        if !action_supports_platform(action, platform) {
            return Err(ActionRegistryError::PlatformUnavailable);
        }
        let inputs = inputs.as_object().ok_or_else(|| {
            ActionRegistryError::InvalidInputs("inputs must be a JSON object".into())
        })?;
        if inputs.len() > config.max_inputs {
            return Err(ActionRegistryError::Capacity);
        }
        for name in inputs.keys() {
            if !action.inputs.contains_key(name) {
                return Err(ActionRegistryError::InvalidInputs(format!(
                    "unexpected input {name}"
                )));
            }
        }
        if inputs.len() != action.inputs.len() {
            return Err(ActionRegistryError::InvalidInputs(
                "all declared inputs are required".into(),
            ));
        }
        let mut argv = Vec::with_capacity(action.argv.len());
        for argument in &action.argv {
            match argument {
                ActionArgSpec::Literal { value } => argv.push(value.clone()),
                ActionArgSpec::Input { name } => {
                    let schema = action.inputs.get(name).ok_or_else(|| {
                        ActionRegistryError::InvalidInputs("undeclared argv input".into())
                    })?;
                    let value = inputs.get(name).ok_or_else(|| {
                        ActionRegistryError::InvalidInputs(format!("missing input {name}"))
                    })?;
                    argv.push(expand_input(name, schema, value, config)?);
                }
            }
        }
        Ok(ActionInvocation {
            executable: action.executable.clone(),
            argv,
        })
    }

    #[must_use]
    pub fn input_schema(action: &ActionSpec) -> Value {
        let mut properties = Map::new();
        for (name, input) in &action.inputs {
            let schema = match input {
                ActionInputSpec::String {
                    max_bytes,
                    allowed_values,
                    ..
                } => {
                    let mut schema = serde_json::json!({
                        "type": "string",
                        "maxLength": max_bytes,
                    });
                    if !allowed_values.is_empty() {
                        schema["enum"] = serde_json::json!(allowed_values);
                    }
                    schema
                }
                ActionInputSpec::Integer { min, max } => serde_json::json!({
                    "type": "integer",
                    "minimum": min,
                    "maximum": max,
                }),
                ActionInputSpec::Boolean { .. } => serde_json::json!({"type": "boolean"}),
            };
            properties.insert(name.clone(), schema);
        }
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": action.inputs.keys().collect::<Vec<_>>(),
            "additionalProperties": false,
        })
    }
}

fn collect_manifests(
    directory: &Path,
    config: &ExtensionsConfig,
    manifests: &mut Vec<PathBuf>,
) -> Result<(), ActionRegistryError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != config.trusted_manifest_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(ActionRegistryError::UnsafeDirectory(
            directory.to_path_buf(),
        ));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.uid() != config.trusted_manifest_owner_uid || metadata.mode() & 0o022 != 0 {
            return Err(ActionRegistryError::UnsafeManifest(path));
        }
        manifests.push(path);
        if manifests.len() > config.max_manifests {
            return Err(ActionRegistryError::Capacity);
        }
    }
    Ok(())
}

fn read_manifest(path: &Path, limit: usize) -> Result<String, ActionRegistryError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if usize::try_from(file.metadata()?.len()).map_or(true, |length| length > limit) {
        return Err(ActionRegistryError::Capacity);
    }
    let mut encoded = String::new();
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_string(&mut encoded)?;
    if encoded.len() > limit {
        return Err(ActionRegistryError::Capacity);
    }
    Ok(encoded)
}

fn validate_action(
    action: &ActionSpec,
    config: &ExtensionsConfig,
) -> Result<(), ActionRegistryError> {
    if !valid_name(&action.id)
        || action.description.trim().is_empty()
        || action.description.len() > 512
        || action.description.chars().any(char::is_control)
        || action.platforms.is_empty()
        || action.platforms.len() > 3
        || action.argv.len() > config.max_argv
        || action.inputs.len() > config.max_inputs
        || !safe_executable(&action.executable)
    {
        return Err(ActionRegistryError::Invalid(action.id.clone()));
    }
    let mut platforms = BTreeSet::new();
    for platform in &action.platforms {
        if !matches!(platform.as_str(), "linux" | "openwrt" | "generic_linux")
            || !platforms.insert(platform)
        {
            return Err(ActionRegistryError::Invalid(action.id.clone()));
        }
    }
    let mut referenced = BTreeSet::new();
    for argument in &action.argv {
        match argument {
            ActionArgSpec::Literal { value } => validate_argument(value, config)?,
            ActionArgSpec::Input { name } => {
                if !valid_name(name) || !action.inputs.contains_key(name) {
                    return Err(ActionRegistryError::Invalid(action.id.clone()));
                }
                referenced.insert(name);
            }
        }
    }
    if referenced.len() != action.inputs.len() {
        return Err(ActionRegistryError::Invalid(format!(
            "{} contains unused inputs",
            action.id
        )));
    }
    for (name, input) in &action.inputs {
        if !valid_name(name) {
            return Err(ActionRegistryError::Invalid(action.id.clone()));
        }
        validate_input_schema(input, config)?;
    }
    validate_shell_boundary(action)?;
    Ok(())
}

fn validate_input_schema(
    input: &ActionInputSpec,
    config: &ExtensionsConfig,
) -> Result<(), ActionRegistryError> {
    match input {
        ActionInputSpec::String {
            max_bytes,
            allowed_values,
            allow_leading_dash,
        } => {
            if *max_bytes == 0 || *max_bytes > config.max_input_bytes || allowed_values.len() > 64 {
                return Err(ActionRegistryError::Capacity);
            }
            for value in allowed_values {
                validate_runtime_string(value, *max_bytes, *allow_leading_dash)?;
            }
        }
        ActionInputSpec::Integer { min, max } if min > max => {
            return Err(ActionRegistryError::Invalid(
                "integer range is empty".into(),
            ));
        }
        ActionInputSpec::Boolean {
            true_value,
            false_value,
        } => {
            validate_argument(true_value, config)?;
            validate_argument(false_value, config)?;
            if true_value == false_value {
                return Err(ActionRegistryError::Invalid(
                    "boolean values must differ".into(),
                ));
            }
        }
        ActionInputSpec::Integer { .. } => {}
    }
    Ok(())
}

fn validate_shell_boundary(action: &ActionSpec) -> Result<(), ActionRegistryError> {
    let Some(script_index) = shell_script_index(&action.executable, &action.argv) else {
        return Ok(());
    };
    if action.argv.iter().any(|argument| {
        matches!(argument, ActionArgSpec::Literal { value } if value == "-c" || value == "-lc")
    }) {
        return Err(ActionRegistryError::Invalid(
            "shell -c is not permitted; reference a fixed script".into(),
        ));
    }
    let Some(ActionArgSpec::Literal { value }) = action.argv.get(script_index) else {
        return Err(ActionRegistryError::Invalid(
            "shell actions require a fixed script as argv[0]".into(),
        ));
    };
    let script = Path::new(value);
    if !safe_executable(script) {
        return Err(ActionRegistryError::Invalid(
            "shell script path is unsafe".into(),
        ));
    }
    Ok(())
}

fn shell_script_index(executable: &Path, argv: &[ActionArgSpec]) -> Option<usize> {
    match executable.file_name().and_then(|value| value.to_str()) {
        Some("sh" | "ash" | "bash" | "dash") => Some(0),
        Some("busybox")
            if matches!(
                argv.first(),
                Some(ActionArgSpec::Literal { value }) if value == "sh" || value == "ash"
            ) =>
        {
            Some(1)
        }
        _ => None,
    }
}

fn expand_input(
    name: &str,
    schema: &ActionInputSpec,
    value: &Value,
    config: &ExtensionsConfig,
) -> Result<String, ActionRegistryError> {
    let expanded = match schema {
        ActionInputSpec::String {
            max_bytes,
            allowed_values,
            allow_leading_dash,
        } => {
            let value = value.as_str().ok_or_else(|| {
                ActionRegistryError::InvalidInputs(format!("{name} must be a string"))
            })?;
            validate_runtime_string(value, *max_bytes, *allow_leading_dash)?;
            if !allowed_values.is_empty() && !allowed_values.iter().any(|item| item == value) {
                return Err(ActionRegistryError::InvalidInputs(format!(
                    "{name} is not an allowed value"
                )));
            }
            value.to_owned()
        }
        ActionInputSpec::Integer { min, max } => {
            let value = value.as_i64().ok_or_else(|| {
                ActionRegistryError::InvalidInputs(format!("{name} must be an integer"))
            })?;
            if value < *min || value > *max {
                return Err(ActionRegistryError::InvalidInputs(format!(
                    "{name} is outside its allowed range"
                )));
            }
            value.to_string()
        }
        ActionInputSpec::Boolean {
            true_value,
            false_value,
        } => match value.as_bool() {
            Some(true) => true_value.clone(),
            Some(false) => false_value.clone(),
            None => {
                return Err(ActionRegistryError::InvalidInputs(format!(
                    "{name} must be a boolean"
                )));
            }
        },
    };
    if expanded.len() > config.max_input_bytes {
        return Err(ActionRegistryError::Capacity);
    }
    Ok(expanded)
}

fn validate_runtime_string(
    value: &str,
    max_bytes: usize,
    allow_leading_dash: bool,
) -> Result<(), ActionRegistryError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || (!allow_leading_dash && value.starts_with('-'))
    {
        return Err(ActionRegistryError::InvalidInputs(
            "string input violates its bound".into(),
        ));
    }
    Ok(())
}

fn validate_argument(value: &str, config: &ExtensionsConfig) -> Result<(), ActionRegistryError> {
    if value.len() > config.max_input_bytes
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(ActionRegistryError::Invalid("argv value is invalid".into()));
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

fn safe_executable(path: &Path) -> bool {
    path.is_absolute()
        && !path.starts_with("/tmp")
        && path.as_os_str().as_encoded_bytes().len() <= 256
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

fn action_supports_platform(action: &ActionSpec, platform: &str) -> bool {
    action.platforms.iter().any(|value| {
        value == platform || (value == "linux" && matches!(platform, "openwrt" | "generic_linux"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> (PathBuf, ExtensionsConfig) {
        let root = std::env::temp_dir().join(format!(
            "mbed-agent-actions-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("permissions");
        let owner = fs::metadata(&root).expect("metadata").uid();
        let config = ExtensionsConfig {
            enabled: true,
            directories: vec![root.clone()],
            trusted_manifest_owner_uid: owner,
            ..ExtensionsConfig::default()
        };
        (root, config)
    }

    fn write_manifest(root: &Path, body: &str) {
        let path = root.join("vendor.toml");
        let mut file = fs::File::create(&path).expect("manifest");
        file.write_all(body.as_bytes()).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("permissions");
    }

    #[test]
    fn loads_and_expands_typed_exec_action() {
        let (root, config) = fixture();
        write_manifest(
            &root,
            r#"
schema_version = 1

[[actions]]
id = "vendor_modem"
description = "Inspect one modem"
platforms = ["linux"]
executable = "/bin/echo"

[[actions.argv]]
kind = "literal"
value = "--modem"

[[actions.argv]]
kind = "input"
name = "modem_id"

[actions.inputs.modem_id]
kind = "integer"
min = 0
max = 8
"#,
        );
        let registry = ActionRegistry::load(&config).expect("registry");
        let invocation = registry
            .invocation(
                "vendor_modem",
                "generic_linux",
                &serde_json::json!({"modem_id": 2}),
                &config,
            )
            .expect("invocation");
        assert_eq!(invocation.executable, Path::new("/bin/echo"));
        assert_eq!(invocation.argv, ["--modem", "2"]);
        assert!(
            registry
                .invocation(
                    "vendor_modem",
                    "generic_linux",
                    &serde_json::json!({"modem_id": 2, "extra": true}),
                    &config,
                )
                .is_err()
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_shell_command_strings_and_extra_inputs() {
        let (root, config) = fixture();
        write_manifest(
            &root,
            r#"
schema_version = 1

[[actions]]
id = "unsafe_shell"
description = "Unsafe"
platforms = ["openwrt"]
executable = "/bin/sh"

[[actions.argv]]
kind = "literal"
value = "-c"

[[actions.argv]]
kind = "literal"
value = "ip route"
"#,
        );
        assert!(ActionRegistry::load(&config).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_writable_or_duplicate_manifests() {
        let (root, config) = fixture();
        write_manifest(
            &root,
            r#"
schema_version = 1
[[actions]]
id = "duplicate"
description = "First"
platforms = ["linux"]
executable = "/bin/true"
"#,
        );
        let second = root.join("second.toml");
        fs::write(
            &second,
            r#"
schema_version = 1
[[actions]]
id = "duplicate"
description = "Second"
platforms = ["linux"]
executable = "/bin/true"
"#,
        )
        .expect("second");
        fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert!(matches!(
            ActionRegistry::load(&config),
            Err(ActionRegistryError::Duplicate(_))
        ));
        fs::set_permissions(&second, fs::Permissions::from_mode(0o622)).expect("permissions");
        assert!(matches!(
            ActionRegistry::load(&config),
            Err(ActionRegistryError::UnsafeManifest(_))
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
