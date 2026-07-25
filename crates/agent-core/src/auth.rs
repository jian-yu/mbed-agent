use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

const ALGORITHM_NAME: &str = "pbkdf2-sha256";
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
pub const MIN_PASSWORD_HASH_ITERATIONS: u32 = 100_000;
pub const MAX_PASSWORD_HASH_ITERATIONS: u32 = 2_000_000;
pub const DEFAULT_PASSWORD_HASH_ITERATIONS: u32 = 200_000;

#[derive(Clone)]
pub struct AdminPasswordVerifier {
    iterations: NonZeroU32,
    salt: [u8; SALT_LEN],
    expected: [u8; HASH_LEN],
}

impl std::fmt::Debug for AdminPasswordVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED PASSWORD VERIFIER]")
    }
}

impl AdminPasswordVerifier {
    /// Parses an encoded PBKDF2-SHA256 password verifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoding, iteration count, salt, or digest is invalid.
    pub fn parse(encoded: &str) -> Result<Self, AuthError> {
        let mut fields = encoded.split('$');
        let algorithm = fields.next();
        let iterations = fields.next();
        let salt = fields.next();
        let expected = fields.next();
        if algorithm != Some(ALGORITHM_NAME)
            || fields.next().is_some()
            || iterations.is_none()
            || salt.is_none()
            || expected.is_none()
        {
            return Err(AuthError::InvalidPasswordHash);
        }

        let iterations = iterations
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| {
                (MIN_PASSWORD_HASH_ITERATIONS..=MAX_PASSWORD_HASH_ITERATIONS).contains(value)
            })
            .and_then(NonZeroU32::new)
            .ok_or(AuthError::InvalidPasswordHash)?;
        let salt = decode_hex_array::<SALT_LEN>(salt.unwrap_or_default())?;
        let expected = decode_hex_array::<HASH_LEN>(expected.unwrap_or_default())?;
        Ok(Self {
            iterations,
            salt,
            expected,
        })
    }

    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            self.iterations,
            &self.salt,
            password,
            &self.expected,
        )
        .is_ok()
    }
}

/// Produces a salted password verifier suitable for `auth.admin_password_hash`.
///
/// # Errors
///
/// Returns an error if the operating system random source is unavailable.
pub fn generate_password_hash(password: &[u8]) -> Result<String, AuthError> {
    if password.is_empty() {
        return Err(AuthError::EmptyPassword);
    }
    let mut salt = [0_u8; SALT_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| AuthError::RandomUnavailable)?;
    Ok(encode_password_hash(
        password,
        &salt,
        DEFAULT_PASSWORD_HASH_ITERATIONS,
    ))
}

fn encode_password_hash(password: &[u8], salt: &[u8; SALT_LEN], iterations: u32) -> String {
    let iterations = NonZeroU32::new(iterations).expect("iterations are non-zero");
    let mut expected = [0_u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut expected,
    );
    format!(
        "{ALGORITHM_NAME}${}${}${}",
        iterations,
        encode_hex(salt),
        encode_hex(&expected)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdminCapability {
    pub actor_id: String,
    pub boot_id: String,
    pub expires_monotonic_ms: u64,
}

#[derive(Debug)]
struct FailureState {
    failures: u8,
    locked_until_monotonic_ms: u64,
}

#[derive(Debug, Default)]
struct VolatileAuthState {
    capabilities: HashMap<String, DeviceAdminCapability>,
    failures: HashMap<String, FailureState>,
}

pub struct AuthManager {
    verifier: Option<AdminPasswordVerifier>,
    boot_id: String,
    capability_ttl_ms: u64,
    max_failures: u8,
    lockout_ms: u64,
    state: Mutex<VolatileAuthState>,
}

impl AuthManager {
    #[must_use]
    pub fn disabled(boot_id: String) -> Self {
        Self {
            verifier: None,
            boot_id,
            capability_ttl_ms: 0,
            max_failures: 1,
            lockout_ms: 0,
            state: Mutex::new(VolatileAuthState::default()),
        }
    }

    #[must_use]
    pub fn new(
        verifier: AdminPasswordVerifier,
        boot_id: String,
        capability_ttl_secs: u64,
        max_failures: u8,
        lockout_secs: u64,
    ) -> Self {
        Self {
            verifier: Some(verifier),
            boot_id,
            capability_ttl_ms: capability_ttl_secs.saturating_mul(1_000),
            max_failures,
            lockout_ms: lockout_secs.saturating_mul(1_000),
            state: Mutex::new(VolatileAuthState::default()),
        }
    }

    /// Verifies the administrator password and grants an in-memory capability.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication is disabled, the actor is invalid,
    /// the actor is locked, the password is incorrect, or the state lock is poisoned.
    pub fn elevate(
        &self,
        actor_id: &str,
        password: &[u8],
        now_monotonic_ms: u64,
    ) -> Result<DeviceAdminCapability, AuthError> {
        validate_actor_id(actor_id)?;
        let verifier = self.verifier.as_ref().ok_or(AuthError::Disabled)?;
        let mut state = self.state.lock().map_err(|_| AuthError::StateUnavailable)?;
        state
            .capabilities
            .retain(|_, capability| capability.expires_monotonic_ms > now_monotonic_ms);
        if let Some(failure) = state.failures.get(actor_id) {
            if failure.locked_until_monotonic_ms > now_monotonic_ms {
                return Err(AuthError::Locked);
            }
        }

        if !verifier.verify(password) {
            let failure = state
                .failures
                .entry(actor_id.to_owned())
                .or_insert(FailureState {
                    failures: 0,
                    locked_until_monotonic_ms: 0,
                });
            if failure.locked_until_monotonic_ms <= now_monotonic_ms {
                failure.locked_until_monotonic_ms = 0;
            }
            failure.failures = failure.failures.saturating_add(1);
            if failure.failures >= self.max_failures {
                failure.failures = 0;
                failure.locked_until_monotonic_ms =
                    now_monotonic_ms.saturating_add(self.lockout_ms);
            }
            return Err(AuthError::InvalidCredentials);
        }

        let capability = DeviceAdminCapability {
            actor_id: actor_id.to_owned(),
            boot_id: self.boot_id.clone(),
            expires_monotonic_ms: now_monotonic_ms.saturating_add(self.capability_ttl_ms),
        };
        state.failures.remove(actor_id);
        state
            .capabilities
            .insert(actor_id.to_owned(), capability.clone());
        Ok(capability)
    }

    /// Checks and lazily expires the actor's boot-bound administrator capability.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory state lock is poisoned.
    pub fn is_device_admin(
        &self,
        actor_id: &str,
        now_monotonic_ms: u64,
    ) -> Result<bool, AuthError> {
        validate_actor_id(actor_id)?;
        let mut state = self.state.lock().map_err(|_| AuthError::StateUnavailable)?;
        let valid = state.capabilities.get(actor_id).is_some_and(|capability| {
            capability.boot_id == self.boot_id && capability.expires_monotonic_ms > now_monotonic_ms
        });
        if !valid {
            state.capabilities.remove(actor_id);
        }
        Ok(valid)
    }
}

fn validate_actor_id(actor_id: &str) -> Result<(), AuthError> {
    if actor_id.is_empty()
        || actor_id.len() > 128
        || !actor_id.is_ascii()
        || actor_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthError::InvalidActor);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_array<const N: usize>(encoded: &str) -> Result<[u8; N], AuthError> {
    if encoded.len() != N * 2 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthError::InvalidPasswordHash);
    }
    let mut output = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, AuthError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AuthError::InvalidPasswordHash),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("administrator authentication is disabled")]
    Disabled,
    #[error("administrator password must not be empty")]
    EmptyPassword,
    #[error("invalid administrator password hash")]
    InvalidPasswordHash,
    #[error("invalid actor identity")]
    InvalidActor,
    #[error("administrator credentials are invalid")]
    InvalidCredentials,
    #[error("administrator authentication is temporarily locked")]
    Locked,
    #[error("operating system randomness is unavailable")]
    RandomUnavailable,
    #[error("volatile authentication state is unavailable")]
    StateUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> AdminPasswordVerifier {
        let encoded = encode_password_hash(b"correct horse", &[7; SALT_LEN], 100_000);
        AdminPasswordVerifier::parse(&encoded).expect("valid verifier")
    }

    #[test]
    fn encoded_password_round_trip_verifies_without_plaintext() {
        let encoded = encode_password_hash(b"correct horse", &[7; SALT_LEN], 100_000);
        assert!(!encoded.contains("correct horse"));
        let parsed = AdminPasswordVerifier::parse(&encoded).expect("valid verifier");
        assert_eq!(format!("{parsed:?}"), "[REDACTED PASSWORD VERIFIER]");
        assert!(parsed.verify(b"correct horse"));
        assert!(!parsed.verify(b"wrong"));
    }

    #[test]
    fn malformed_or_weak_password_hash_is_rejected() {
        assert!(matches!(
            AdminPasswordVerifier::parse("pbkdf2-sha256$1$00$00"),
            Err(AuthError::InvalidPasswordHash)
        ));
        assert!(matches!(
            AdminPasswordVerifier::parse(
                "pbkdf2-sha256$100000$07070707070707070707070707070707$\
                 000000000000000000000000000000000000000000000000000000000000000g"
            ),
            Err(AuthError::InvalidPasswordHash)
        ));
    }

    #[test]
    fn capability_is_actor_boot_and_monotonic_time_bound() {
        let manager = AuthManager::new(verifier(), "boot-a".into(), 30, 3, 60);
        let capability = manager
            .elevate("channel/wecom/user-1", b"correct horse", 1_000)
            .expect("elevated");
        assert_eq!(capability.boot_id, "boot-a");
        assert_eq!(capability.expires_monotonic_ms, 31_000);
        assert!(
            manager
                .is_device_admin("channel/wecom/user-1", 30_999)
                .expect("state")
        );
        assert!(
            !manager
                .is_device_admin("channel/wecom/user-1", 31_000)
                .expect("state")
        );
        assert!(
            !manager
                .is_device_admin("channel/mqtt/user-1", 2_000)
                .expect("state")
        );
    }

    #[test]
    fn repeated_failure_locks_only_the_actor_and_success_clears_failures() {
        let manager = AuthManager::new(verifier(), "boot-a".into(), 30, 2, 60);
        assert_eq!(
            manager.elevate("actor-a", b"wrong", 1),
            Err(AuthError::InvalidCredentials)
        );
        assert_eq!(
            manager.elevate("actor-a", b"wrong", 2),
            Err(AuthError::InvalidCredentials)
        );
        assert_eq!(
            manager.elevate("actor-a", b"correct horse", 3),
            Err(AuthError::Locked)
        );
        assert!(manager.elevate("actor-b", b"correct horse", 3).is_ok());
        assert!(manager.elevate("actor-a", b"correct horse", 60_002).is_ok());
        assert_eq!(
            manager.elevate("actor-a", b"wrong", 60_003),
            Err(AuthError::InvalidCredentials)
        );
        assert!(manager.elevate("actor-a", b"correct horse", 60_004).is_ok());
    }
}
