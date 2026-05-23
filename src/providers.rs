//! Built-in provider routing.
//! Maps path prefixes to upstream API base URLs.
//! When no --target is specified, mirage acts as a multi-provider proxy.

use crate::config::CustomProvider;

pub struct Provider {
    pub name: &'static str,
    pub prefix: &'static str,
    pub upstream: &'static str,
}

/// All supported providers. Path prefix → upstream URL.
/// Clients set their base URL to http://localhost:8686/{prefix}
pub static PROVIDERS: &[Provider] = &[
    // Major LLM providers
    Provider { name: "Anthropic",       prefix: "/anthropic",    upstream: "https://api.anthropic.com" },
    Provider { name: "OpenAI",          prefix: "/openai",       upstream: "https://api.openai.com" },
    Provider { name: "Google AI",       prefix: "/google",       upstream: "https://generativelanguage.googleapis.com" },
    Provider { name: "Google Vertex",   prefix: "/vertex",       upstream: "https://us-central1-aiplatform.googleapis.com" },
    Provider { name: "Mistral",         prefix: "/mistral",      upstream: "https://api.mistral.ai" },
    Provider { name: "Cohere",          prefix: "/cohere",       upstream: "https://api.cohere.com" },
    Provider { name: "Perplexity",      prefix: "/perplexity",   upstream: "https://api.perplexity.ai" },

    // Chinese / Asian providers
    Provider { name: "DeepSeek",        prefix: "/deepseek",     upstream: "https://api.deepseek.com" },
    Provider { name: "Alibaba Qwen",    prefix: "/alibaba",      upstream: "https://dashscope.aliyuncs.com" },
    Provider { name: "Zhipu / GLM",     prefix: "/zhipu",        upstream: "https://open.bigmodel.cn" },
    Provider { name: "Moonshot / Kimi",  prefix: "/moonshot",    upstream: "https://api.moonshot.cn" },
    Provider { name: "Baichuan",        prefix: "/baichuan",     upstream: "https://api.baichuan-ai.com" },
    Provider { name: "Yi / 01.AI",      prefix: "/yi",           upstream: "https://api.lingyiwanwu.com" },
    Provider { name: "Minimax",         prefix: "/minimax",      upstream: "https://api.minimax.chat" },
    Provider { name: "Stepfun",         prefix: "/stepfun",      upstream: "https://api.stepfun.com" },
    Provider { name: "SiliconFlow",     prefix: "/siliconflow",  upstream: "https://api.siliconflow.cn" },

    // Open / self-hosted compatible
    Provider { name: "Groq",           prefix: "/groq",         upstream: "https://api.groq.com" },
    Provider { name: "Together",       prefix: "/together",     upstream: "https://api.together.xyz" },
    Provider { name: "Fireworks",      prefix: "/fireworks",    upstream: "https://api.fireworks.ai" },
    Provider { name: "Anyscale",       prefix: "/anyscale",     upstream: "https://api.endpoints.anyscale.com" },
    Provider { name: "Replicate",      prefix: "/replicate",    upstream: "https://api.replicate.com" },
    Provider { name: "Lepton",         prefix: "/lepton",       upstream: "https://api.lepton.ai" },
    Provider { name: "Cerebras",       prefix: "/cerebras",     upstream: "https://api.cerebras.ai" },
    Provider { name: "SambaNova",      prefix: "/sambanova",    upstream: "https://api.sambanova.ai" },

    // Cloud provider AI
    Provider { name: "Azure OpenAI",   prefix: "/azure",        upstream: "https://YOUR_RESOURCE.openai.azure.com" },
    Provider { name: "AWS Bedrock",    prefix: "/bedrock",      upstream: "https://bedrock-runtime.us-east-1.amazonaws.com" },

    // AI coding / agent platforms
    Provider { name: "OpenRouter",     prefix: "/openrouter",   upstream: "https://openrouter.ai" },
    Provider { name: "xAI / Grok",     prefix: "/xai",          upstream: "https://api.x.ai" },
];

/// Strip a prefix from a path and normalize the remaining portion.
/// Ensures the result always starts with '/'.
fn strip_prefix(path: &str, prefix: &str) -> String {
    let remaining = &path[prefix.len()..];
    if remaining.is_empty() {
        "/".to_string()
    } else if remaining.starts_with('/') {
        remaining.to_string()
    } else {
        format!("/{remaining}")
    }
}

/// Resolve a custom provider prefix match, returning (upstream, remaining_path).
fn resolve_custom_provider<'a>(path: &str, custom_providers: &'a [CustomProvider]) -> Option<(&'a str, String)> {
    for cp in custom_providers {
        if path.starts_with(&cp.prefix) {
            let remaining = strip_prefix(path, &cp.prefix);
            return Some((&cp.upstream, remaining));
        }
    }
    None
}

/// Resolve a request path to (upstream_base_url, remaining_path).
/// If a provider prefix matches, strip it and return the upstream.
/// Falls back to auto-detection for common API paths.
/// Returns None if nothing matches (use --target fallback).
///
/// `is_chatgpt_account`: true if the request has a `chatgpt-account-id` header,
/// indicating it uses ChatGPT account auth (e.g. Codex CLI with ChatGPT Plus).
/// These requests go to chatgpt.com/backend-api/codex/* instead of api.openai.com.
pub fn resolve_provider<'a>(
    path: &str,
    is_chatgpt_account: bool,
    custom_providers: &'a [CustomProvider],
) -> Option<(&'a str, String)> {
    // Custom providers checked first — allows overriding built-in entries
    if let Some(result) = resolve_custom_provider(path, custom_providers) {
        return Some(result);
    }

    // Explicit prefix match
    for p in PROVIDERS {
        if path.starts_with(p.prefix) {
            let remaining = strip_prefix(path, p.prefix);
            return Some((p.upstream, remaining));
        }
    }

    // ChatGPT account auth (Codex CLI with ChatGPT Plus/Pro/Team subscription)
    // Routes to chatgpt.com/backend-api/codex/* instead of api.openai.com
    if is_chatgpt_account {
        // /responses → /backend-api/codex/responses
        // /models → /backend-api/codex/models
        if path.starts_with("/responses")
            || path.starts_with("/models")
        {
            return Some(("https://chatgpt.com", format!("/backend-api/codex{}", path)));
        }
        // /v1/* → strip /v1 and route to /backend-api/codex/*
        if path.starts_with("/v1/") {
            return Some(("https://chatgpt.com", format!("/backend-api/codex{}", &path[3..])));
        }
    }

    // Standard OpenAI API paths (API key auth)
    // /v1/* passes through as-is (client already includes prefix).
    if path.starts_with("/v1/") {
        return Some(("https://api.openai.com", path.to_string()));
    }
    // /responses — Responses API (no /v1/ prefix for API key auth)
    if path.starts_with("/responses") {
        return Some(("https://api.openai.com", path.to_string()));
    }
    if path.starts_with("/chat/completions")
        || path.starts_with("/completions")
        || path.starts_with("/embeddings")
        || path.starts_with("/models")
    {
        return Some(("https://api.openai.com", format!("/v1{}", path)));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CustomProvider;

    #[test]
    fn custom_provider_resolves_before_builtin() {
        let custom = vec![CustomProvider {
            prefix: "/openai".to_string(),
            upstream: "https://custom-openai.example.com".to_string(),
        }];
        let result = resolve_provider("/openai/v1/chat/completions", false, &custom);
        assert!(result.is_some());
        let (upstream, remaining) = result.unwrap();
        assert_eq!(upstream, "https://custom-openai.example.com");
        assert_eq!(remaining, "/v1/chat/completions");
    }

    #[test]
    fn custom_provider_returns_correct_upstream() {
        let custom = vec![CustomProvider {
            prefix: "/nanogpt".to_string(),
            upstream: "https://nano-gpt.com/api/v1".to_string(),
        }];
        let result = resolve_provider("/nanogpt/chat/completions", false, &custom);
        assert!(result.is_some());
        let (upstream, remaining) = result.unwrap();
        assert_eq!(upstream, "https://nano-gpt.com/api/v1");
        assert_eq!(remaining, "/chat/completions");
    }

    #[test]
    fn empty_custom_providers_falls_through_to_builtin() {
        let custom: Vec<CustomProvider> = vec![];
        let result = resolve_provider("/openai/v1/chat/completions", false, &custom);
        assert!(result.is_some());
        let (upstream, remaining) = result.unwrap();
        assert_eq!(upstream, "https://api.openai.com");
        assert_eq!(remaining, "/v1/chat/completions");
    }

    #[test]
    fn custom_provider_no_match_falls_through() {
        let custom = vec![CustomProvider {
            prefix: "/nanogpt".to_string(),
            upstream: "https://nano-gpt.com/api/v1".to_string(),
        }];
        let result = resolve_provider("/anthropic/v1/messages", false, &custom);
        assert!(result.is_some());
        let (upstream, _) = result.unwrap();
        assert_eq!(upstream, "https://api.anthropic.com");
    }

    #[test]
    fn custom_provider_path_with_prefix_overlap() {
        let custom = vec![CustomProvider {
            prefix: "/nanogpt/v1".to_string(),
            upstream: "https://nano-gpt.com/api/v1".to_string(),
        }];
        let result = resolve_provider("/nanogpt/v1/chat/completions", false, &custom);
        assert!(result.is_some());
        let (upstream, remaining) = result.unwrap();
        assert_eq!(upstream, "https://nano-gpt.com/api/v1");
        assert_eq!(remaining, "/chat/completions");
    }

    #[test]
    fn custom_provider_prefix_root_only() {
        let custom = vec![CustomProvider {
            prefix: "/".to_string(),
            upstream: "https://catch-all.example.com".to_string(),
        }];
        let result = resolve_provider("/any/path", false, &custom);
        assert!(result.is_some());
        let (upstream, remaining) = result.unwrap();
        assert_eq!(upstream, "https://catch-all.example.com");
        assert_eq!(remaining, "/any/path");
    }
}
