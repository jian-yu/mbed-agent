//! Boot-bound canonical firewall inventory for generic Linux.
//!
//! Native `nftables`/`iptables` output cannot reconstruct the complete typed model without
//! losing intent. The Agent therefore keeps its typed inventory in volatile `SQLite` and binds it
//! to a digest of the freshly inspected, strictly Agent-owned native state.

use std::collections::HashSet;

use agent_core::{FirewallInventory, FirewallMutationPlan, validate_firewall_object};
use agent_protocol::ObjectOwnership;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::firewall_command::{FirewallCommand, FirewallCommandExecutor};
use crate::firewall_iptables::{
    IptablesFamilyState, IptablesFirewallStage, IptablesRenderError, inspect_iptables_family_state,
    iptables_owned_state_digest, render_iptables_firewall_stage,
};
use crate::firewall_nft::{
    NftablesFirewallStage, NftablesRenderError, NftablesTableState, inspect_nftables_table_state,
    nftables_managed_table_exists, nftables_owned_state_digest, render_nftables_firewall_stage,
};
use crate::firewall_project::{FirewallProjectionError, project_agent_objects};

const SCHEMA_VERSION: u32 = 1;
const MAX_CANONICAL_STATE_BYTES: usize = 256 * 1024;
const MAX_OBJECTS: usize = 256;
const MAX_BOOT_ID_BYTES: usize = 128;

/// Supported generic Linux firewall control planes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericFirewallBackend {
    Nftables,
    Iptables,
}

/// Fresh native output gathered immediately before planning or applying.
#[derive(Debug, Clone, Copy)]
pub enum GenericFirewallObservation<'a> {
    /// `None` means the fixed `inet mbed_agent` table is natively absent.
    Nftables(Option<&'a str>),
    /// Complete outputs from `iptables-save` and `ip6tables-save`.
    Iptables {
        ipv4_save: &'a str,
        ipv6_save: &'a str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NativeFingerprint {
    Nftables {
        digest: String,
    },
    Iptables {
        ipv4_digest: String,
        ipv6_digest: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalState {
    schema_version: u32,
    boot_id: String,
    backend: GenericFirewallBackend,
    inventory: FirewallInventory,
    native: NativeFingerprint,
}

/// Immutable typed inventory proven against one fresh native observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericFirewallInventorySnapshot {
    boot_id: String,
    backend: GenericFirewallBackend,
    inventory: FirewallInventory,
    native: Option<NativeFingerprint>,
}

impl GenericFirewallInventorySnapshot {
    #[must_use]
    pub fn inventory(&self) -> &FirewallInventory {
        &self.inventory
    }

    #[must_use]
    pub const fn backend(&self) -> GenericFirewallBackend {
        self.backend
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
}

/// One owned native nftables observation collected by the closed command runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedNftablesObservation {
    managed_listing: Option<String>,
}

/// One paired IPv4/IPv6 iptables observation collected without a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIptablesObservation {
    ipv4_save: String,
    ipv6_save: String,
}

impl CollectedIptablesObservation {
    #[must_use]
    pub fn ipv4_save(&self) -> &str {
        &self.ipv4_save
    }

    #[must_use]
    pub fn ipv6_save(&self) -> &str {
        &self.ipv6_save
    }
}

/// Collects both address families as one bounded logical observation.
///
/// # Errors
///
/// Returns an error when either fixed save command fails or emits non-UTF-8 data.
pub fn collect_iptables_observation(
    executor: &impl FirewallCommandExecutor,
) -> Result<CollectedIptablesObservation, GenericFirewallStateError> {
    let ipv4 = executor
        .execute(&FirewallCommand::IptablesSave { ipv6: false }, None)
        .map_err(|_| GenericFirewallStateError::NativeInspection)?
        .stdout;
    let ipv6 = executor
        .execute(&FirewallCommand::IptablesSave { ipv6: true }, None)
        .map_err(|_| GenericFirewallStateError::NativeInspection)?
        .stdout;
    Ok(CollectedIptablesObservation {
        ipv4_save: String::from_utf8(ipv4)
            .map_err(|_| GenericFirewallStateError::NativeInspection)?,
        ipv6_save: String::from_utf8(ipv6)
            .map_err(|_| GenericFirewallStateError::NativeInspection)?,
    })
}

/// Reconciles an already collected paired iptables observation.
///
/// # Errors
///
/// Returns an error for partial/foreign ownership, stale canonical state, or native drift.
pub fn reconcile_iptables_observation(
    canonical_state: Option<&[u8]>,
    boot_id: &str,
    observation: &CollectedIptablesObservation,
) -> Result<GenericFirewallInventorySnapshot, GenericFirewallStateError> {
    inspect_generic_firewall_inventory(
        canonical_state,
        boot_id,
        GenericFirewallBackend::Iptables,
        GenericFirewallObservation::Iptables {
            ipv4_save: observation.ipv4_save(),
            ipv6_save: observation.ipv6_save(),
        },
    )
}

/// Collects and reconciles a fresh dual-stack iptables inventory.
///
/// # Errors
///
/// Returns an error for native command/format failures or canonical-state mismatch.
pub fn inspect_generic_iptables_inventory(
    executor: &impl FirewallCommandExecutor,
    canonical_state: Option<&[u8]>,
    boot_id: &str,
) -> Result<GenericFirewallInventorySnapshot, GenericFirewallStateError> {
    let observation = collect_iptables_observation(executor)?;
    reconcile_iptables_observation(canonical_state, boot_id, &observation)
}

impl CollectedNftablesObservation {
    #[must_use]
    pub fn managed_listing(&self) -> Option<&str> {
        self.managed_listing.as_deref()
    }
}

/// Collects the exact fixed-table presence and optional table listing.
///
/// # Errors
///
/// Returns an error for command failures, non-UTF-8 output, or malformed declarations.
pub fn collect_nftables_observation(
    executor: &impl FirewallCommandExecutor,
) -> Result<CollectedNftablesObservation, GenericFirewallStateError> {
    let tables = executor
        .execute(&FirewallCommand::NftListTables, None)
        .map_err(|_| GenericFirewallStateError::NativeInspection)?
        .stdout;
    let tables =
        std::str::from_utf8(&tables).map_err(|_| GenericFirewallStateError::NativeInspection)?;
    let managed_listing = if nftables_managed_table_exists(tables)? {
        let output = executor
            .execute(&FirewallCommand::NftListManagedTable, None)
            .map_err(|_| GenericFirewallStateError::NativeInspection)?
            .stdout;
        Some(String::from_utf8(output).map_err(|_| GenericFirewallStateError::NativeInspection)?)
    } else {
        None
    };
    Ok(CollectedNftablesObservation { managed_listing })
}

/// Reconciles one already collected observation with volatile canonical state.
///
/// # Errors
///
/// Returns an error for corrupt/stale canonical state, foreign ownership, orphaned native state,
/// or native drift.
pub fn reconcile_nftables_observation(
    canonical_state: Option<&[u8]>,
    boot_id: &str,
    observation: &CollectedNftablesObservation,
) -> Result<GenericFirewallInventorySnapshot, GenericFirewallStateError> {
    inspect_generic_firewall_inventory(
        canonical_state,
        boot_id,
        GenericFirewallBackend::Nftables,
        GenericFirewallObservation::Nftables(observation.managed_listing()),
    )
}

/// Collects a fresh generic Linux nftables observation through closed commands and reconciles it
/// with the volatile canonical state.
///
/// # Errors
///
/// Returns an error for command failures, non-UTF-8/malformed output, foreign ownership,
/// canonical-state corruption, or native drift.
pub fn inspect_generic_nftables_inventory(
    executor: &impl FirewallCommandExecutor,
    canonical_state: Option<&[u8]>,
    boot_id: &str,
) -> Result<GenericFirewallInventorySnapshot, GenericFirewallStateError> {
    let observation = collect_nftables_observation(executor)?;
    reconcile_nftables_observation(canonical_state, boot_id, &observation)
}

/// Reconciles volatile canonical state with a fresh native firewall observation.
///
/// First use is allowed only when both canonical and native Agent-owned state are absent. Native
/// state without its boot-bound canonical record is treated as orphaned and never adopted.
///
/// # Errors
///
/// Returns an error for corrupt, oversized, stale, foreign, partial, or drifted state.
pub fn inspect_generic_firewall_inventory(
    canonical_state: Option<&[u8]>,
    boot_id: &str,
    backend: GenericFirewallBackend,
    observation: GenericFirewallObservation<'_>,
) -> Result<GenericFirewallInventorySnapshot, GenericFirewallStateError> {
    validate_boot_id(boot_id)?;
    let native = inspect_native(backend, observation)?;
    let Some(encoded) = canonical_state else {
        if native.is_some() {
            return Err(GenericFirewallStateError::OrphanedNativeState);
        }
        return Ok(GenericFirewallInventorySnapshot {
            boot_id: boot_id.to_owned(),
            backend,
            inventory: FirewallInventory {
                objects: Vec::new(),
            },
            native: None,
        });
    };
    if encoded.len() > MAX_CANONICAL_STATE_BYTES {
        return Err(GenericFirewallStateError::Capacity);
    }
    let canonical: CanonicalState =
        serde_json::from_slice(encoded).map_err(|_| GenericFirewallStateError::CorruptState)?;
    if canonical.schema_version != SCHEMA_VERSION
        || canonical.boot_id != boot_id
        || canonical.backend != backend
    {
        return Err(GenericFirewallStateError::StaleState);
    }
    validate_inventory(&canonical.inventory)?;
    if native.as_ref() != Some(&canonical.native) {
        return Err(GenericFirewallStateError::NativeDrift);
    }
    Ok(GenericFirewallInventorySnapshot {
        boot_id: canonical.boot_id,
        backend,
        inventory: canonical.inventory,
        native,
    })
}

/// Encodes the projected inventory after independently inspecting the applied native state.
///
/// # Errors
///
/// Returns an error when the plan is stale, the post-state is absent/wrong-backend, or the
/// bounded canonical representation cannot be produced.
pub fn encode_applied_generic_firewall_state(
    snapshot: &GenericFirewallInventorySnapshot,
    plan: &FirewallMutationPlan,
    boot_id: &str,
    post_observation: GenericFirewallObservation<'_>,
) -> Result<Vec<u8>, GenericFirewallStateError> {
    validate_boot_id(boot_id)?;
    if snapshot.boot_id != boot_id {
        return Err(GenericFirewallStateError::StaleState);
    }
    let native = inspect_native(snapshot.backend, post_observation)?
        .ok_or(GenericFirewallStateError::NativeStateMissing)?;
    let objects = project_agent_objects(&snapshot.inventory, plan).map_err(map_projection_error)?;
    let canonical = CanonicalState {
        schema_version: SCHEMA_VERSION,
        boot_id: boot_id.to_owned(),
        backend: snapshot.backend,
        inventory: FirewallInventory { objects },
        native,
    };
    let encoded =
        serde_json::to_vec(&canonical).map_err(|_| GenericFirewallStateError::CorruptState)?;
    if encoded.len() > MAX_CANONICAL_STATE_BYTES {
        return Err(GenericFirewallStateError::Capacity);
    }
    Ok(encoded)
}

/// Renders an `nftables` stage only from a reconciled snapshot.
///
/// # Errors
///
/// Returns an error for the wrong backend or an invalid/stale typed plan.
pub fn render_nftables_stage_from_snapshot(
    snapshot: &GenericFirewallInventorySnapshot,
    plan: &FirewallMutationPlan,
) -> Result<NftablesFirewallStage, GenericFirewallStateError> {
    if snapshot.backend != GenericFirewallBackend::Nftables {
        return Err(GenericFirewallStateError::BackendMismatch);
    }
    let state = if snapshot.native.is_some() {
        NftablesTableState::AgentOwned
    } else {
        NftablesTableState::Absent
    };
    render_nftables_firewall_stage(&snapshot.inventory, plan, state)
        .map_err(GenericFirewallStateError::Nftables)
}

/// Renders dual-stack `iptables` stages only from a reconciled snapshot.
///
/// # Errors
///
/// Returns an error for the wrong backend or an invalid/stale typed plan.
pub fn render_iptables_stage_from_snapshot(
    snapshot: &GenericFirewallInventorySnapshot,
    plan: &FirewallMutationPlan,
) -> Result<IptablesFirewallStage, GenericFirewallStateError> {
    if snapshot.backend != GenericFirewallBackend::Iptables {
        return Err(GenericFirewallStateError::BackendMismatch);
    }
    let state = if snapshot.native.is_some() {
        IptablesFamilyState::AgentOwned
    } else {
        IptablesFamilyState::Absent
    };
    render_iptables_firewall_stage(&snapshot.inventory, plan, state, state)
        .map_err(GenericFirewallStateError::Iptables)
}

fn inspect_native(
    backend: GenericFirewallBackend,
    observation: GenericFirewallObservation<'_>,
) -> Result<Option<NativeFingerprint>, GenericFirewallStateError> {
    match (backend, observation) {
        (GenericFirewallBackend::Nftables, GenericFirewallObservation::Nftables(listing)) => {
            match inspect_nftables_table_state(listing)? {
                NftablesTableState::Absent => Ok(None),
                NftablesTableState::AgentOwned => {
                    let listing = listing.ok_or(GenericFirewallStateError::NativeStateMissing)?;
                    Ok(Some(NativeFingerprint::Nftables {
                        digest: nftables_owned_state_digest(listing)?,
                    }))
                }
            }
        }
        (
            GenericFirewallBackend::Iptables,
            GenericFirewallObservation::Iptables {
                ipv4_save,
                ipv6_save,
            },
        ) => {
            let ipv4 = inspect_iptables_family_state(ipv4_save)?;
            let ipv6 = inspect_iptables_family_state(ipv6_save)?;
            match (ipv4, ipv6) {
                (IptablesFamilyState::Absent, IptablesFamilyState::Absent) => Ok(None),
                (IptablesFamilyState::AgentOwned, IptablesFamilyState::AgentOwned) => {
                    Ok(Some(NativeFingerprint::Iptables {
                        ipv4_digest: iptables_owned_state_digest(ipv4_save)?,
                        ipv6_digest: iptables_owned_state_digest(ipv6_save)?,
                    }))
                }
                _ => Err(GenericFirewallStateError::PartialFamilyState),
            }
        }
        _ => Err(GenericFirewallStateError::BackendMismatch),
    }
}

fn validate_boot_id(boot_id: &str) -> Result<(), GenericFirewallStateError> {
    if boot_id.is_empty()
        || boot_id.len() > MAX_BOOT_ID_BYTES
        || boot_id.bytes().any(|byte| {
            byte.is_ascii_control()
                || !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(GenericFirewallStateError::InvalidBootId);
    }
    Ok(())
}

fn validate_inventory(inventory: &FirewallInventory) -> Result<(), GenericFirewallStateError> {
    if inventory.objects.len() > MAX_OBJECTS {
        return Err(GenericFirewallStateError::Capacity);
    }
    let mut identities = HashSet::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_firewall_object(object).map_err(|_| GenericFirewallStateError::CorruptState)?;
        if object.ownership() != ObjectOwnership::AgentOwned
            || !identities.insert((object.kind(), object.id()))
        {
            return Err(GenericFirewallStateError::CorruptState);
        }
    }
    Ok(())
}

fn map_projection_error(error: FirewallProjectionError) -> GenericFirewallStateError {
    match error {
        FirewallProjectionError::InvalidObject => GenericFirewallStateError::CorruptState,
        FirewallProjectionError::Ownership => GenericFirewallStateError::Ownership,
        FirewallProjectionError::PlanMismatch => GenericFirewallStateError::PlanMismatch,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenericFirewallStateError {
    #[error("generic firewall native inspection failed")]
    NativeInspection,
    #[error("generic firewall backend and native observation do not match")]
    BackendMismatch,
    #[error("generic firewall canonical state is malformed")]
    CorruptState,
    #[error("generic firewall canonical state exceeds its capacity")]
    Capacity,
    #[error("generic firewall boot identifier is invalid")]
    InvalidBootId,
    #[error("generic firewall canonical state belongs to another boot or backend")]
    StaleState,
    #[error("Agent-owned native firewall state has no volatile canonical record")]
    OrphanedNativeState,
    #[error("native firewall state no longer matches the canonical inventory")]
    NativeDrift,
    #[error("native firewall state is absent after application")]
    NativeStateMissing,
    #[error("iptables and ip6tables Agent-owned state is partial")]
    PartialFamilyState,
    #[error("generic firewall canonical state contains non-Agent-owned objects")]
    Ownership,
    #[error("generic firewall mutation plan does not match the reconciled inventory")]
    PlanMismatch,
    #[error("nftables state error: {0}")]
    Nftables(#[from] NftablesRenderError),
    #[error("iptables state error: {0}")]
    Iptables(#[from] IptablesRenderError),
}

#[cfg(test)]
mod tests {
    use agent_core::{FirewallMutation, FirewallRiskContext, plan_firewall_mutations};
    use agent_protocol::{FirewallObject, FirewallVerdict, FirewallZone, ObjectOwnership};

    use super::*;
    use crate::firewall_command::{FirewallCommandError, FirewallCommandOutput};

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    struct NftObservation {
        tables: &'static str,
        managed: Option<&'static str>,
    }

    impl FirewallCommandExecutor for NftObservation {
        fn execute(
            &self,
            operation: &FirewallCommand,
            _stdin: Option<&[u8]>,
        ) -> Result<FirewallCommandOutput, FirewallCommandError> {
            let value = match operation {
                FirewallCommand::NftListTables => self.tables,
                FirewallCommand::NftListManagedTable => {
                    self.managed.ok_or(FirewallCommandError::Unsuccessful)?
                }
                _ => return Err(FirewallCommandError::UnexpectedInput),
            };
            Ok(FirewallCommandOutput {
                stdout: value.as_bytes().to_vec(),
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            })
        }
    }

    #[test]
    fn first_use_requires_native_state_to_be_absent() {
        let collected = inspect_generic_nftables_inventory(
            &NftObservation {
                tables: "table ip filter\n",
                managed: None,
            },
            None,
            BOOT_ID,
        )
        .expect("collected first use");
        assert!(collected.inventory().objects.is_empty());
        let snapshot = inspect_generic_firewall_inventory(
            None,
            BOOT_ID,
            GenericFirewallBackend::Nftables,
            GenericFirewallObservation::Nftables(None),
        )
        .expect("empty first use");
        assert!(snapshot.inventory().objects.is_empty());
        assert_eq!(
            inspect_generic_firewall_inventory(
                None,
                BOOT_ID,
                GenericFirewallBackend::Nftables,
                GenericFirewallObservation::Nftables(Some(owned_nft()))
            ),
            Err(GenericFirewallStateError::OrphanedNativeState)
        );
    }

    #[test]
    fn applied_state_round_trips_and_detects_native_drift() {
        let snapshot = inspect_generic_firewall_inventory(
            None,
            BOOT_ID,
            GenericFirewallBackend::Nftables,
            GenericFirewallObservation::Nftables(None),
        )
        .expect("snapshot");
        let plan = plan_firewall_mutations(
            snapshot.inventory(),
            &[FirewallMutation::Create(FirewallObject::Zone(
                FirewallZone {
                    id: "lan".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    networks: vec!["lan0".into()],
                    input: FirewallVerdict::Accept,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Drop,
                    masquerade: false,
                    mtu_fix: false,
                },
            ))],
            &FirewallRiskContext::default(),
        )
        .expect("plan");
        let encoded = encode_applied_generic_firewall_state(
            &snapshot,
            &plan,
            BOOT_ID,
            GenericFirewallObservation::Nftables(Some(owned_nft())),
        )
        .expect("encode");
        let restored = inspect_generic_firewall_inventory(
            Some(&encoded),
            BOOT_ID,
            GenericFirewallBackend::Nftables,
            GenericFirewallObservation::Nftables(Some(owned_nft())),
        )
        .expect("restore");
        assert_eq!(restored.inventory().objects.len(), 1);

        let drifted = owned_nft().replace("chain input { }", "chain input { drop }");
        assert_eq!(
            inspect_generic_firewall_inventory(
                Some(&encoded),
                BOOT_ID,
                GenericFirewallBackend::Nftables,
                GenericFirewallObservation::Nftables(Some(&drifted)),
            ),
            Err(GenericFirewallStateError::NativeDrift)
        );
    }

    #[test]
    fn canonical_state_is_boot_bound() {
        let state = CanonicalState {
            schema_version: SCHEMA_VERSION,
            boot_id: BOOT_ID.into(),
            backend: GenericFirewallBackend::Nftables,
            inventory: FirewallInventory {
                objects: Vec::new(),
            },
            native: NativeFingerprint::Nftables {
                digest: nftables_owned_state_digest(owned_nft()).expect("digest"),
            },
        };
        let encoded = serde_json::to_vec(&state).expect("json");
        assert_eq!(
            inspect_generic_firewall_inventory(
                Some(&encoded),
                "other-boot",
                GenericFirewallBackend::Nftables,
                GenericFirewallObservation::Nftables(Some(owned_nft())),
            ),
            Err(GenericFirewallStateError::StaleState)
        );
    }

    fn owned_nft() -> &'static str {
        "table inet mbed_agent {\n comment \"mbed-agent-owned:v1\"\n chain input { }\n}\n"
    }
}
