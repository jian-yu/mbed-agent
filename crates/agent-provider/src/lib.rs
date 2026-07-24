use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_output_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub text: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

pub struct OpenAiCompatibleProvider {
    client: Client,
    endpoint: reqwest::Url,
    api_key: String,
    model: String,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl OpenAiCompatibleProvider {
    /// Creates a bounded OpenAI-compatible provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed or a limit is zero.
    pub fn new(
        base_url: &str,
        api_key: String,
        model: String,
        connect_timeout: Duration,
        request_timeout: Duration,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if max_request_bytes == 0 || max_response_bytes == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "request and response limits must be greater than zero".into(),
            ));
        }
        if api_key.is_empty() || model.trim().is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "API key and model must not be empty".into(),
            ));
        }
        let endpoint = reqwest::Url::parse(&format!(
            "{}/chat/completions",
            base_url.trim_end_matches('/')
        ))
        .map_err(|error| ProviderError::InvalidConfiguration(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ProviderError::InvalidConfiguration(
                "base URL must be HTTP(S), include a host, and exclude credentials, query, and fragment"
                    .into(),
            ));
        }
        let _installed = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mbed-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ProviderError::Client)?;
        Ok(Self {
            client,
            endpoint,
            api_key,
            model,
            max_request_bytes,
            max_response_bytes,
        })
    }

    /// Requests one non-streaming completion.
    ///
    /// # Errors
    ///
    /// Returns a typed error for transport, size, HTTP, or response-shape failures.
    pub async fn complete(&self, request: CompletionRequest) -> Result<Completion, ProviderError> {
        let payload = ApiRequest {
            model: &self.model,
            messages: [
                ApiMessage {
                    role: "system",
                    content: &request.system_prompt,
                },
                ApiMessage {
                    role: "user",
                    content: &request.user_prompt,
                },
            ],
            max_tokens: request.max_output_tokens,
            stream: false,
        };
        let encoded = serde_json::to_vec(&payload).map_err(ProviderError::Encode)?;
        if encoded.len() > self.max_request_bytes {
            return Err(ProviderError::RequestTooLarge {
                actual: encoded.len(),
                limit: self.max_request_bytes,
            });
        }

        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.api_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(encoded)
            .send()
            .await
            .map_err(ProviderError::Transport)?;
        let status = response.status();
        let body = read_bounded(response, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(ProviderError::Http {
                status,
                message: error_message(&body),
            });
        }
        let response: ApiResponse = serde_json::from_slice(&body).map_err(ProviderError::Decode)?;
        let choice = response
            .choices
            .into_iter()
            .next()
            .ok_or(ProviderError::MissingChoice)?;
        Ok(Completion {
            text: choice.message.content,
            model: response.model,
            finish_reason: choice.finish_reason,
            prompt_tokens: response
                .usage
                .as_ref()
                .and_then(|usage| usage.prompt_tokens),
            completion_tokens: response
                .usage
                .as_ref()
                .and_then(|usage| usage.completion_tokens),
        })
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        return Err(ProviderError::ResponseTooLarge { limit });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(4096)
            .min(limit),
    );
    while let Some(chunk) = response.chunk().await.map_err(ProviderError::Transport)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ProviderError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn error_message(body: &[u8]) -> String {
    serde_json::from_slice::<ApiErrorEnvelope>(body)
        .ok()
        .map_or_else(
            || String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned(),
            |error| error.error.message,
        )
}

#[derive(Serialize)]
struct ApiRequest<'a> {
    model: &'a str,
    messages: [ApiMessage<'a>; 2],
    max_tokens: u32,
    stream: bool,
}

#[derive(Serialize)]
struct ApiMessage<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ApiResponse {
    model: String,
    choices: Vec<ApiChoice>,
    #[serde(default)]
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct ApiChoice {
    message: ApiResponseMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ApiResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct ApiUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct ApiErrorEnvelope {
    error: ApiError,
}

#[derive(Deserialize)]
struct ApiError {
    message: String,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid provider configuration: {0}")]
    InvalidConfiguration(String),
    #[error("failed to construct HTTP client: {0}")]
    Client(reqwest::Error),
    #[error("failed to encode provider request: {0}")]
    Encode(serde_json::Error),
    #[error("provider request is {actual} bytes, exceeding the {limit}-byte limit")]
    RequestTooLarge { actual: usize, limit: usize },
    #[error("provider transport failed: {0}")]
    Transport(reqwest::Error),
    #[error("provider response exceeds the {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("provider returned HTTP {status}: {message}")]
    Http { status: StatusCode, message: String },
    #[error("failed to decode provider response: {0}")]
    Decode(serde_json::Error),
    #[error("provider response contained no completion choice")]
    MissingChoice,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn parses_bounded_completion() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.expect("read");
            let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
            assert!(request.contains("authorization: bearer test-key"));
            let body = r#"{"model":"mock-model","choices":[{"message":{"content":"ready"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        let provider = OpenAiCompatibleProvider::new(
            &format!("http://{address}/v1"),
            "test-key".into(),
            "mock-model".into(),
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
            4096,
        )
        .expect("provider");
        let completion = provider
            .complete(CompletionRequest {
                system_prompt: "system".into(),
                user_prompt: "status".into(),
                max_output_tokens: 32,
            })
            .await
            .expect("completion");
        assert_eq!(completion.text, "ready");
        assert_eq!(completion.prompt_tokens, Some(3));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn rejects_content_length_over_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                .await
                .expect("write");
        });
        let provider = OpenAiCompatibleProvider::new(
            &format!("http://{address}/v1"),
            "key".into(),
            "model".into(),
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
            16,
        )
        .expect("provider");
        let error = provider
            .complete(CompletionRequest {
                system_prompt: "system".into(),
                user_prompt: "status".into(),
                max_output_tokens: 32,
            })
            .await
            .expect_err("oversized");
        assert!(matches!(
            error,
            ProviderError::ResponseTooLarge { limit: 16 }
        ));
    }
}
