/// Built-in provider routing.
/// Maps path prefixes to upstream API base URLs.
/// When no --target is specified, mirage acts as a multi-provider proxy.

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

/// Resolve a request path to (upstream_base_url, remaining_path).
/// If a provider prefix matches, strip it and return the upstream.
/// Falls back to auto-detection for common API paths.
/// Returns None if nothing matches (use --target fallback).
pub fn resolve_provider(path: &str) -> Option<(&'static str, String)> {
    // Explicit prefix match
    for p in PROVIDERS {
        if path.starts_with(p.prefix) {
            let remaining = &path[p.prefix.len()..];
            let remaining = if remaining.is_empty() { "/" } else { remaining };
            return Some((p.upstream, remaining.to_string()));
        }
    }

    // Auto-detect common OpenAI paths (Codex uses /responses, /v1/chat/completions, etc.)
    if path.starts_with("/v1/") || path.starts_with("/responses") {
        return Some(("https://api.openai.com", path.to_string()));
    }

    None
}
