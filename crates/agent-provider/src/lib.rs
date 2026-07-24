use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub messages: Vec<ModelMessage>,
    pub tools: Vec<ToolDefinition>,
    pub max_output_tokens: u32,
    pub streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelMessage {
    Instruction(String),
    User(String),
    Assistant {
        content: String,
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        tool_call_id: String,
        content: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub text: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub tool_calls: Vec<ToolCall>,
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
        if request.messages.is_empty() {
            return Err(ProviderError::InvalidRequest(
                "at least one model message is required".into(),
            ));
        }
        let messages = request.messages.iter().map(ApiMessage::from).collect();
        let tools = request.tools.iter().map(ApiToolDefinition::from).collect();
        let payload = ApiRequest {
            model: &self.model,
            messages,
            tools,
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
        let tool_calls = validate_api_tool_calls(choice.message.tool_calls)?;
        Ok(Completion {
            text: choice.message.content.unwrap_or_default(),
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
            tool_calls,
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
    messages: Vec<ApiMessage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ApiToolDefinition<'a>>,
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
#[serde(tag = "role", rename_all = "lowercase")]
enum ApiMessage<'a> {
    #[serde(rename = "system")]
    Instruction {
        content: &'a str,
    },
    User {
        content: &'a str,
    },
    Assistant {
        content: Option<&'a str>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ApiToolCallRef<'a>>,
    },
    Tool {
        tool_call_id: &'a str,
        content: &'a str,
    },
}

impl<'a> From<&'a ModelMessage> for ApiMessage<'a> {
    fn from(message: &'a ModelMessage) -> Self {
        match message {
            ModelMessage::Instruction(content) => Self::Instruction { content },
            ModelMessage::User(content) => Self::User { content },
            ModelMessage::Assistant {
                content,
                tool_calls,
            } => Self::Assistant {
                content: (!content.is_empty()).then_some(content),
                tool_calls: tool_calls.iter().map(ApiToolCallRef::from).collect(),
            },
            ModelMessage::Tool {
                tool_call_id,
                content,
            } => Self::Tool {
                tool_call_id,
                content,
            },
        }
    }
}

#[derive(Serialize)]
struct ApiToolDefinition<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: ApiFunctionDefinition<'a>,
}

impl<'a> From<&'a ToolDefinition> for ApiToolDefinition<'a> {
    fn from(tool: &'a ToolDefinition) -> Self {
        Self {
            kind: "function",
            function: ApiFunctionDefinition {
                name: &tool.name,
                description: &tool.description,
                parameters: &tool.parameters,
            },
        }
    }
}

#[derive(Serialize)]
struct ApiFunctionDefinition<'a> {
    name: &'a str,
    description: &'a str,
    parameters: &'a Value,
}

#[derive(Serialize)]
struct ApiToolCallRef<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    function: ApiFunctionCallRef<'a>,
}

impl<'a> From<&'a ToolCall> for ApiToolCallRef<'a> {
    fn from(call: &'a ToolCall) -> Self {
        Self {
            id: &call.id,
            kind: "function",
            function: ApiFunctionCallRef {
                name: &call.name,
                arguments: &call.arguments,
            },
        }
    }
}

#[derive(Serialize)]
struct ApiFunctionCallRef<'a> {
    name: &'a str,
    arguments: &'a str,
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
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ApiToolCall>,
}

#[derive(Deserialize)]
struct ApiToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: ApiFunctionCall,
}

#[derive(Deserialize)]
struct ApiFunctionCall {
    name: String,
    arguments: String,
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
    #[serde(default)]
    tool_calls: Vec<ApiStreamToolCall>,
}

#[derive(Deserialize)]
struct ApiStreamToolCall {
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    function: Option<ApiStreamFunctionCall>,
}

#[derive(Deserialize)]
struct ApiStreamFunctionCall {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

struct StreamAggregate {
    text: String,
    model: String,
    finish_reason: Option<String>,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    tool_calls: Vec<ToolCallBuilder>,
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
            tool_calls: Vec::new(),
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
            for tool_call in choice.delta.tool_calls {
                self.consume_tool_call(tool_call)?;
            }
            if choice.finish_reason.is_some() {
                self.finish_reason = choice.finish_reason;
            }
        }
        Ok(())
    }

    fn consume_tool_call(&mut self, delta: ApiStreamToolCall) -> Result<(), ProviderError> {
        if delta.index >= MAX_PROVIDER_TOOL_CALLS {
            return Err(ProviderError::InvalidToolCall(format!(
                "tool-call index {} exceeds provider limit {}",
                delta.index, MAX_PROVIDER_TOOL_CALLS
            )));
        }
        while self.tool_calls.len() <= delta.index {
            self.tool_calls.push(ToolCallBuilder::default());
        }
        let builder = &mut self.tool_calls[delta.index];
        if let Some(kind) = delta.kind {
            if kind != "function" {
                return Err(ProviderError::InvalidToolCall(format!(
                    "unsupported tool-call type {kind}"
                )));
            }
            builder.saw_function_type = true;
        }
        if let Some(id) = delta.id {
            builder.id.push_str(&id);
        }
        if let Some(function) = delta.function {
            if let Some(name) = function.name {
                builder.name.push_str(&name);
            }
            if let Some(arguments) = function.arguments {
                builder.arguments.push_str(&arguments);
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
        let tool_calls = self
            .tool_calls
            .into_iter()
            .map(ToolCallBuilder::finish)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Completion {
            text: self.text,
            model: self.model,
            finish_reason: self.finish_reason,
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            tool_calls,
        })
    }
}

const MAX_PROVIDER_TOOL_CALLS: usize = 8;
const MAX_TOOL_CALL_ID_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 128;

#[derive(Default)]
struct ToolCallBuilder {
    id: String,
    name: String,
    arguments: String,
    saw_function_type: bool,
}

impl ToolCallBuilder {
    fn finish(self) -> Result<ToolCall, ProviderError> {
        validate_tool_call(self.id, self.name, self.arguments, self.saw_function_type)
    }
}

fn validate_api_tool_calls(calls: Vec<ApiToolCall>) -> Result<Vec<ToolCall>, ProviderError> {
    if calls.len() > MAX_PROVIDER_TOOL_CALLS {
        return Err(ProviderError::InvalidToolCall(format!(
            "response contains {} tool calls; limit is {MAX_PROVIDER_TOOL_CALLS}",
            calls.len()
        )));
    }
    calls
        .into_iter()
        .map(|call| {
            validate_tool_call(
                call.id,
                call.function.name,
                call.function.arguments,
                call.kind == "function",
            )
        })
        .collect()
}

fn validate_tool_call(
    id: String,
    name: String,
    arguments: String,
    is_function: bool,
) -> Result<ToolCall, ProviderError> {
    if !is_function {
        return Err(ProviderError::InvalidToolCall(
            "only function tool calls are supported".into(),
        ));
    }
    if id.is_empty() || id.len() > MAX_TOOL_CALL_ID_BYTES {
        return Err(ProviderError::InvalidToolCall(
            "tool-call ID is empty or too long".into(),
        ));
    }
    if name.is_empty() || name.len() > MAX_TOOL_NAME_BYTES {
        return Err(ProviderError::InvalidToolCall(
            "tool name is empty or too long".into(),
        ));
    }
    Ok(ToolCall {
        id,
        name,
        arguments,
    })
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
    #[error("invalid provider request: {0}")]
    InvalidRequest(String),
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
    #[error("invalid provider tool call: {0}")]
    InvalidToolCall(String),
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
            assert!(request.contains("\"name\":\"diagnose_wan\""));
            assert!(request.contains("\"additionalproperties\":false"));
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
                messages: vec![
                    ModelMessage::Instruction("system".into()),
                    ModelMessage::User("status".into()),
                ],
                tools: vec![ToolDefinition {
                    name: "diagnose_wan".into(),
                    description: "Read WAN state".into(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }),
                }],
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
                messages: vec![
                    ModelMessage::Instruction("system".into()),
                    ModelMessage::User("status".into()),
                ],
                tools: vec![],
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
                messages: vec![
                    ModelMessage::Instruction("system".into()),
                    ModelMessage::User("status".into()),
                ],
                tools: vec![],
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

    #[test]
    fn aggregates_fragmented_stream_tool_call() {
        let mut aggregate = StreamAggregate::new("model".into());
        aggregate
            .consume(
                br#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_","type":"function","function":{"name":"diagnose_","arguments":"{"}}]},"finish_reason":null}]}"#,
            )
            .expect("first tool delta");
        aggregate
            .consume(
                br#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"1","function":{"name":"wan","arguments":"}"}}]},"finish_reason":"tool_calls"}]}"#,
            )
            .expect("second tool delta");
        aggregate.consume(b"[DONE]").expect("done");
        let completion = aggregate.finish().expect("completion");
        assert_eq!(
            completion.tool_calls,
            vec![ToolCall {
                id: "call_1".into(),
                name: "diagnose_wan".into(),
                arguments: "{}".into(),
            }]
        );
    }

    #[test]
    fn rejects_non_function_tool_call() {
        let error = validate_tool_call("call_1".into(), "tool".into(), "{}".into(), false)
            .expect_err("custom tool rejected");
        assert!(matches!(error, ProviderError::InvalidToolCall(_)));
    }
}
