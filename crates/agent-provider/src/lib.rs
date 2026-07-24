use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_output_tokens: u32,
    pub streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub text: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

pub struct OpenAiCompatibleConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stream_event_bytes: usize,
}

pub struct OpenAiCompatibleProvider {
    client: Client,
    endpoint: reqwest::Url,
    api_key: String,
    model: String,
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_stream_event_bytes: usize,
}

impl OpenAiCompatibleProvider {
    /// Creates a bounded OpenAI-compatible provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed or a limit is zero.
    pub fn new(config: OpenAiCompatibleConfig) -> Result<Self, ProviderError> {
        if config.max_request_bytes == 0
            || config.max_response_bytes == 0
            || config.max_stream_event_bytes == 0
            || config.max_stream_event_bytes > config.max_response_bytes
        {
            return Err(ProviderError::InvalidConfiguration(
                "request/response limits must be non-zero and stream events must fit the response limit"
                    .into(),
            ));
        }
        if config.api_key.is_empty() || config.model.trim().is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "API key and model must not be empty".into(),
            ));
        }
        let endpoint = reqwest::Url::parse(&format!(
            "{}/chat/completions",
            config.base_url.trim_end_matches('/')
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
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mbed-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ProviderError::Client)?;
        Ok(Self {
            client,
            endpoint,
            api_key: config.api_key,
            model: config.model,
            max_request_bytes: config.max_request_bytes,
            max_response_bytes: config.max_response_bytes,
            max_stream_event_bytes: config.max_stream_event_bytes,
        })
    }

    /// Requests one bounded completion, optionally using an SSE stream.
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
            stream: request.streaming,
            stream_options: request.streaming.then_some(ApiStreamOptions {
                include_usage: true,
            }),
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
        if !status.is_success() {
            let body = read_bounded(response, self.max_response_bytes).await?;
            return Err(ProviderError::Http {
                status,
                message: error_message(&body),
            });
        }
        if request.streaming {
            return self.read_streaming(response).await;
        }
        let body = read_bounded(response, self.max_response_bytes).await?;
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

    async fn read_streaming(
        &self,
        mut response: reqwest::Response,
    ) -> Result<Completion, ProviderError> {
        if response
            .content_length()
            .is_some_and(|length| length > usize_to_u64(self.max_response_bytes))
        {
            return Err(ProviderError::ResponseTooLarge {
                limit: self.max_response_bytes,
            });
        }
        let mut decoder = SseDecoder::new(self.max_stream_event_bytes);
        let mut aggregate = StreamAggregate::new(self.model.clone());
        let mut wire_bytes = 0_usize;
        while let Some(chunk) = response.chunk().await.map_err(ProviderError::Transport)? {
            wire_bytes = wire_bytes.saturating_add(chunk.len());
            if wire_bytes > self.max_response_bytes {
                return Err(ProviderError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            for event in decoder.feed(&chunk)? {
                aggregate.consume(&event)?;
            }
        }
        for event in decoder.finish()? {
            aggregate.consume(&event)?;
        }
        aggregate.finish()
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > usize_to_u64(limit))
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

const fn usize_to_u64(value: usize) -> u64 {
    value as u64
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
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<ApiStreamOptions>,
}

#[derive(Serialize)]
struct ApiStreamOptions {
    include_usage: bool,
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
struct ApiStreamChunk {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    choices: Vec<ApiStreamChoice>,
    #[serde(default)]
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct ApiStreamChoice {
    index: usize,
    #[serde(default)]
    delta: ApiStreamDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Default, Deserialize)]
struct ApiStreamDelta {
    #[serde(default)]
    content: Option<String>,
}

struct StreamAggregate {
    text: String,
    model: String,
    finish_reason: Option<String>,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    saw_choice: bool,
    done: bool,
}

impl StreamAggregate {
    fn new(model: String) -> Self {
        Self {
            text: String::new(),
            model,
            finish_reason: None,
            prompt_tokens: None,
            completion_tokens: None,
            saw_choice: false,
            done: false,
        }
    }

    fn consume(&mut self, event: &[u8]) -> Result<(), ProviderError> {
        if event == b"[DONE]" {
            self.done = true;
            return Ok(());
        }
        if self.done {
            return Err(ProviderError::StreamProtocol(
                "received data after [DONE]".into(),
            ));
        }
        let chunk: ApiStreamChunk = serde_json::from_slice(event).map_err(ProviderError::Decode)?;
        if let Some(model) = chunk.model {
            self.model = model;
        }
        if let Some(usage) = chunk.usage {
            self.prompt_tokens = usage.prompt_tokens;
            self.completion_tokens = usage.completion_tokens;
        }
        if let Some(choice) = chunk.choices.into_iter().find(|choice| choice.index == 0) {
            self.saw_choice = true;
            if let Some(content) = choice.delta.content {
                self.text.push_str(&content);
            }
            if choice.finish_reason.is_some() {
                self.finish_reason = choice.finish_reason;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Completion, ProviderError> {
        if !self.done {
            return Err(ProviderError::IncompleteStream);
        }
        if !self.saw_choice {
            return Err(ProviderError::MissingChoice);
        }
        Ok(Completion {
            text: self.text,
            model: self.model,
            finish_reason: self.finish_reason,
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
        })
    }
}

struct SseDecoder {
    line: Vec<u8>,
    data: Vec<u8>,
    max_event_bytes: usize,
}

impl SseDecoder {
    fn new(max_event_bytes: usize) -> Self {
        Self {
            line: Vec::new(),
            data: Vec::new(),
            max_event_bytes,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProviderError> {
        let mut events = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                self.process_line(&mut events)?;
            } else {
                if self.line.len() >= self.max_event_bytes {
                    return Err(ProviderError::StreamEventTooLarge {
                        limit: self.max_event_bytes,
                    });
                }
                self.line.push(*byte);
            }
        }
        Ok(events)
    }

    fn finish(mut self) -> Result<Vec<Vec<u8>>, ProviderError> {
        let mut events = Vec::new();
        if !self.line.is_empty() {
            self.process_line(&mut events)?;
        }
        if !self.data.is_empty() {
            events.push(self.take_event());
        }
        Ok(events)
    }

    fn process_line(&mut self, events: &mut Vec<Vec<u8>>) -> Result<(), ProviderError> {
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        if self.line.is_empty() {
            if !self.data.is_empty() {
                events.push(self.take_event());
            }
            return Ok(());
        }
        if self.line.first() != Some(&b':') {
            if let Some(value) = self.line.strip_prefix(b"data:") {
                let value = value.strip_prefix(b" ").unwrap_or(value);
                if self
                    .data
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(1)
                    > self.max_event_bytes
                {
                    return Err(ProviderError::StreamEventTooLarge {
                        limit: self.max_event_bytes,
                    });
                }
                self.data.extend_from_slice(value);
                self.data.push(b'\n');
            }
        }
        self.line.clear();
        Ok(())
    }

    fn take_event(&mut self) -> Vec<u8> {
        if self.data.last() == Some(&b'\n') {
            self.data.pop();
        }
        std::mem::take(&mut self.data)
    }
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
    #[error("provider stream event exceeds the {limit}-byte limit")]
    StreamEventTooLarge { limit: usize },
    #[error("provider stream ended before data: [DONE]")]
    IncompleteStream,
    #[error("invalid provider stream: {0}")]
    StreamProtocol(String),
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
        let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
            base_url: format!("http://{address}/v1"),
            api_key: "test-key".into(),
            model: "mock-model".into(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_request_bytes: 4096,
            max_response_bytes: 4096,
            max_stream_event_bytes: 1024,
        })
        .expect("provider");
        let completion = provider
            .complete(CompletionRequest {
                system_prompt: "system".into(),
                user_prompt: "status".into(),
                max_output_tokens: 32,
                streaming: false,
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
        let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
            base_url: format!("http://{address}/v1"),
            api_key: "key".into(),
            model: "model".into(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_request_bytes: 4096,
            max_response_bytes: 16,
            max_stream_event_bytes: 8,
        })
        .expect("provider");
        let error = provider
            .complete(CompletionRequest {
                system_prompt: "system".into(),
                user_prompt: "status".into(),
                max_output_tokens: 32,
                streaming: false,
            })
            .await
            .expect_err("oversized");
        assert!(matches!(
            error,
            ProviderError::ResponseTooLarge { limit: 16 }
        ));
    }

    #[test]
    fn sse_decoder_handles_fragmented_crlf_and_multiline_data() {
        let mut decoder = SseDecoder::new(128);
        assert!(decoder.feed(b": ping\r\nda").expect("first").is_empty());
        assert!(
            decoder
                .feed(b"ta: {\"a\":\r\ndata: 1}\r\n\r\n")
                .expect("second")
                .iter()
                .any(|event| event == b"{\"a\":\n1}")
        );
    }

    #[test]
    fn sse_decoder_rejects_oversized_event() {
        let mut decoder = SseDecoder::new(8);
        let error = decoder
            .feed(b"data: 123456789\n\n")
            .expect_err("oversized event");
        assert!(matches!(
            error,
            ProviderError::StreamEventTooLarge { limit: 8 }
        ));
    }

    #[tokio::test]
    async fn aggregates_stream_and_final_usage_chunk() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.expect("read");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains("\"stream\":true"));
            assert!(request.contains("\"include_usage\":true"));
            let events = concat!(
                "data: {\"model\":\"mock-stream\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"rea\"},\"finish_reason\":null}],\"usage\":null}\n\n",
                "data: {\"model\":\"mock-stream\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"dy\"},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
                "data: {\"model\":\"mock-stream\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\n",
                "data: [DONE]\n\n"
            );
            let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            stream.write_all(header.as_bytes()).await.expect("header");
            for bytes in events.as_bytes().chunks(17) {
                let chunk_header = format!("{:x}\r\n", bytes.len());
                stream
                    .write_all(chunk_header.as_bytes())
                    .await
                    .expect("chunk header");
                stream.write_all(bytes).await.expect("chunk");
                stream.write_all(b"\r\n").await.expect("chunk end");
            }
            stream.write_all(b"0\r\n\r\n").await.expect("end");
        });
        let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
            base_url: format!("http://{address}/v1"),
            api_key: "test-key".into(),
            model: "mock-model".into(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_request_bytes: 4096,
            max_response_bytes: 4096,
            max_stream_event_bytes: 1024,
        })
        .expect("provider");
        let completion = provider
            .complete(CompletionRequest {
                system_prompt: "system".into(),
                user_prompt: "status".into(),
                max_output_tokens: 32,
                streaming: true,
            })
            .await
            .expect("stream completion");
        assert_eq!(completion.text, "ready");
        assert_eq!(completion.model, "mock-stream");
        assert_eq!(completion.finish_reason.as_deref(), Some("stop"));
        assert_eq!(completion.prompt_tokens, Some(3));
        assert_eq!(completion.completion_tokens, Some(1));
        server.await.expect("server");
    }

    #[test]
    fn aggregate_requires_done_marker() {
        let mut aggregate = StreamAggregate::new("model".into());
        aggregate
            .consume(
                br#"{"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}"#,
            )
            .expect("chunk");
        assert!(matches!(
            aggregate.finish(),
            Err(ProviderError::IncompleteStream)
        ));
    }
}
