use std::collections::HashMap;

use agent_core::{FirewallInventory, FirewallMutationPlan, validate_firewall_object};
use agent_protocol::{ChangeOperation, FirewallObject, ObjectOwnership};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallProjectionError {
    InvalidObject,
    Ownership,
    PlanMismatch,
}

pub(crate) fn project_agent_objects(
    inventory: &FirewallInventory,
    plan: &FirewallMutationPlan,
) -> Result<Vec<FirewallObject>, FirewallProjectionError> {
    let mut objects = HashMap::new();
    for object in &inventory.objects {
        validate_firewall_object(object).map_err(|_| FirewallProjectionError::InvalidObject)?;
        if object.ownership() == ObjectOwnership::AgentOwned {
            objects.insert(
                (object.kind().to_owned(), object.id().to_owned()),
                object.clone(),
            );
        }
    }
    for change in &plan.changes {
        if let Some(before) = &change.before {
            validate_firewall_object(before).map_err(|_| FirewallProjectionError::InvalidObject)?;
        }
        if let Some(after) = &change.after {
            validate_firewall_object(after).map_err(|_| FirewallProjectionError::InvalidObject)?;
        }
        let changed = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(FirewallProjectionError::PlanMismatch)?;
        if change.diff.object.kind != changed.kind()
            || change.diff.object.id != changed.id()
            || change.diff.object.ownership != ObjectOwnership::AgentOwned
            || changed.ownership() != ObjectOwnership::AgentOwned
            || change
                .before
                .as_ref()
                .is_some_and(|object| object.ownership() != ObjectOwnership::AgentOwned)
            || change
                .after
                .as_ref()
                .is_some_and(|object| object.ownership() != ObjectOwnership::AgentOwned)
        {
            return Err(FirewallProjectionError::Ownership);
        }
        let key = (changed.kind().to_owned(), changed.id().to_owned());
        match change.diff.operation {
            ChangeOperation::Create => {
                let after = change
                    .after
                    .as_ref()
                    .filter(|_| change.before.is_none())
                    .ok_or(FirewallProjectionError::PlanMismatch)?;
                if objects.insert(key, after.clone()).is_some() {
                    return Err(FirewallProjectionError::PlanMismatch);
                }
            }
            ChangeOperation::Update | ChangeOperation::Move => {
                let before = change
                    .before
                    .as_ref()
                    .ok_or(FirewallProjectionError::PlanMismatch)?;
                let after = change
                    .after
                    .as_ref()
                    .ok_or(FirewallProjectionError::PlanMismatch)?;
                if objects.get(&key) != Some(before) {
                    return Err(FirewallProjectionError::PlanMismatch);
                }
                objects.insert(key, after.clone());
            }
            ChangeOperation::Delete => {
                let before = change
                    .before
                    .as_ref()
                    .filter(|_| change.after.is_none())
                    .ok_or(FirewallProjectionError::PlanMismatch)?;
                if objects.get(&key) != Some(before) {
                    return Err(FirewallProjectionError::PlanMismatch);
                }
                objects.remove(&key);
            }
        }
    }
    let mut projected: Vec<FirewallObject> = objects.into_values().collect();
    projected.sort_by(|left, right| {
        left.kind()
            .cmp(right.kind())
            .then_with(|| left.id().cmp(right.id()))
    });
    Ok(projected)
}
