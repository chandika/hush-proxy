//! Auto-generated secret detection patterns from Gitleaks and secrets-patterns-db.
//! Sources:
//!   - Gitleaks (MIT): https://github.com/gitleaks/gitleaks
//!   - secrets-patterns-db (Apache 2.0): https://github.com/mazen160/secrets-patterns-db
//!
//! Generated: 2026-02-20
//! Only high-confidence, prefix-based and structural patterns included.
//! Generic "keyword near value" patterns excluded to minimize false positives.
//!
//! Pattern counts by category:
//!   AWS / Cloud providers:         12
//!   AI / ML platforms:              7
//!   Version control (GitHub/Lab):  19
//!   Communication (Slack, Discord): 9
//!   Payment / Commerce:            10
//!   Developer tools:               24
//!   Monitoring / Observability:     7
//!   Structural (keys, JWTs, DSNs): 11
//!   Other SaaS prefixed tokens:    30
//!   Total:                        129

use crate::redactor::PiiKind;

pub struct SecretPattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub kind: PiiKind,
}

/// High-confidence secret patterns with distinctive prefixes or structures.
/// These are safe to use in a live proxy because they have very low false-positive rates.
/// Only patterns matching tokens that are structurally self-identifying are included.
pub static SECRET_PATTERNS: &[SecretPattern] = &[
    // ─── AWS / Amazon ─────────────────────────────────────────────────────────
    SecretPattern {
        name: "AWS Access Key",
        regex: r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
        kind: PiiKind::AwsKey,
    },
    SecretPattern {
        name: "AWS Bedrock API Key (Long-lived)",
        regex: r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b",
        kind: PiiKind::AwsKey,
    },
    SecretPattern {
        name: "AWS AppSync GraphQL Key",
        regex: r"\bda2-[a-z0-9]{26}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Google / GCP ─────────────────────────────────────────────────────────
    SecretPattern {
        name: "GCP API Key",
        regex: r"\bAIza[\w-]{35}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Google OAuth Access Token",
        regex: r"\bya29\.[0-9A-Za-z_-]{20,}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        // Matches the JSON field that identifies a GCP service account key file
        name: "GCP Service Account JSON",
        regex: r#""type"\s*:\s*"service_account""#,
        kind: PiiKind::GenericApiKey,
    },

    // ─── Azure ────────────────────────────────────────────────────────────────
    SecretPattern {
        // Azure AD client secrets have a distinctive Q~ marker after 3 alphanum chars + digit.
        // The r#"..."# raw string allows backtick (`) to appear without escaping.
        // Character class: backslash, apostrophe, quote, backtick, whitespace.
        name: "Azure AD Client Secret",
        regex: r#"(?:^|[\\'"`\s>=:(,)])([a-zA-Z0-9_~.]{3}[0-9]Q~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"`\s<),])"#,
        kind: PiiKind::GenericApiKey,
    },

    // ─── DigitalOcean ─────────────────────────────────────────────────────────
    SecretPattern {
        name: "DigitalOcean Personal Access Token",
        regex: r"\bdop_v1_[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "DigitalOcean OAuth Access Token",
        regex: r"\bdoo_v1_[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "DigitalOcean OAuth Refresh Token",
        regex: r"\bdor_v1_[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Alibaba Cloud ────────────────────────────────────────────────────────
    SecretPattern {
        name: "Alibaba Cloud Access Key ID",
        regex: r"\bLTAI[a-zA-Z0-9]{17,21}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Anthropic ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Anthropic API Key",
        regex: r"\bsk-ant-api03-[a-zA-Z0-9_-]{93}AA\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Anthropic Admin API Key",
        regex: r"\bsk-ant-admin01-[a-zA-Z0-9_-]{93}AA\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── OpenAI ───────────────────────────────────────────────────────────────
    SecretPattern {
        // Old format has T3BlbkFJ (base64 of "OpenAI") embedded; new format uses proj/svcacct/admin prefix
        name: "OpenAI API Key (old format with T3BlbkFJ marker)",
        regex: r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "OpenAI API Key (new project/service format)",
        regex: r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,74}T3BlbkFJ[A-Za-z0-9_-]{58,74}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Perplexity AI ────────────────────────────────────────────────────────
    SecretPattern {
        name: "Perplexity API Key",
        regex: r"\bpplx-[a-zA-Z0-9]{48}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── HuggingFace ──────────────────────────────────────────────────────────
    SecretPattern {
        name: "HuggingFace Access Token",
        regex: r"\bhf_[a-zA-Z]{34}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "HuggingFace Organization API Token",
        regex: r"\bapi_org_[a-zA-Z]{34}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── GitHub ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "GitHub Personal Access Token (Classic)",
        regex: r"\bghp_[0-9a-zA-Z]{36}\b",
        kind: PiiKind::GithubToken,
    },
    SecretPattern {
        name: "GitHub Fine-Grained PAT",
        regex: r"\bgithub_pat_\w{82}\b",
        kind: PiiKind::GithubToken,
    },
    SecretPattern {
        name: "GitHub OAuth Token",
        regex: r"\bgho_[0-9a-zA-Z]{36}\b",
        kind: PiiKind::GithubToken,
    },
    SecretPattern {
        name: "GitHub App Installation Token",
        regex: r"\bghs_[0-9a-zA-Z]{36}\b",
        kind: PiiKind::GithubToken,
    },
    SecretPattern {
        name: "GitHub App User-to-Server Token",
        regex: r"\bghu_[0-9a-zA-Z]{36}\b",
        kind: PiiKind::GithubToken,
    },
    SecretPattern {
        name: "GitHub Refresh Token",
        regex: r"\bghr_[0-9a-zA-Z]{36}\b",
        kind: PiiKind::GithubToken,
    },

    // ─── GitLab ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "GitLab Personal Access Token",
        regex: r"\bglpat-[\w-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab PAT (Routable / Instance-prefixed)",
        regex: r"\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{9}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab CI/CD Job Token",
        regex: r"\bglcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Deploy Token",
        regex: r"\bgldt-[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Feature Flag Client Token",
        regex: r"\bglffct-[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Feed Token",
        regex: r"\bglft-[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Incoming Mail Token",
        regex: r"\bglimt-[0-9a-zA-Z_-]{25}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Kubernetes Agent Token",
        regex: r"\bglagent-[0-9a-zA-Z_-]{50}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab OAuth App Secret",
        regex: r"\bgloas-[0-9a-zA-Z_-]{64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Pipeline Trigger Token",
        regex: r"\bglptt-[0-9a-f]{40}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Runner Registration Token",
        regex: r"\bGR1348941[\w-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab Runner Authentication Token",
        regex: r"\bglrt-[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "GitLab SCIM Token",
        regex: r"\bglsoat-[0-9a-zA-Z_-]{20}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Slack ────────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Slack Bot Token",
        regex: r"\bxoxb-[0-9]{8,14}-[0-9]{8,14}-[a-zA-Z0-9]{24}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack App-Level Token",
        regex: r"\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack User Token",
        regex: r"\bxox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack Legacy Token",
        regex: r"\bxox[os]-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]+\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack Legacy Workspace Token",
        regex: r"\bxox[ar]-(?:[0-9]+-)?[0-9a-zA-Z]{8,48}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack Config Access Token",
        regex: r"\bxoxe\.xox[bp]-[0-9]-[A-Z0-9]{163,166}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack Config Refresh Token",
        regex: r"\bxoxe-[0-9]-[A-Z0-9]{146}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Slack Incoming Webhook URL",
        regex: r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Discord ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Discord Webhook URL",
        regex: r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,72}",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Stripe ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Stripe Secret / Restricted Key",
        regex: r"\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Square ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Square Access Token",
        regex: r"\b(?:EAAA|sq0atp-)[\w-]{22,60}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Shopify ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Shopify Access Token",
        regex: r"\bshpat_[a-fA-F0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Shopify Custom Access Token",
        regex: r"\bshpca_[a-fA-F0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Shopify Private App Token",
        regex: r"\bshppa_[a-fA-F0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Shopify Shared Secret",
        regex: r"\bshpss_[a-fA-F0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Flutterwave ──────────────────────────────────────────────────────────
    SecretPattern {
        name: "Flutterwave Secret Key (Test, 32-char)",
        regex: r"\bFLWSECK_TEST-[a-zA-Z0-9]{32}-X\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Flutterwave Secret Key (Production)",
        regex: r"\bFLWSECK-[a-zA-Z0-9]{32}-X\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Flutterwave Public Key (Test)",
        regex: r"\bFLWPUBK_TEST-[a-zA-Z0-9]{32}-X\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── SendGrid ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "SendGrid API Token",
        // SG. followed by 22-char base64 ID, dot, 43-char base64 secret
        regex: r"\bSG\.[a-zA-Z0-9=_-]{22}\.[a-zA-Z0-9=_-]{43}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Sendinblue / Brevo ───────────────────────────────────────────────────
    SecretPattern {
        name: "Sendinblue (Brevo) API Token",
        regex: r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Mailchimp ────────────────────────────────────────────────────────────
    SecretPattern {
        // Format: <32 lowercase hex>-us<1-2 datacenter digits>
        name: "Mailchimp API Key",
        regex: r"\b[a-f0-9]{32}-us[0-9]{1,2}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Twilio ───────────────────────────────────────────────────────────────
    SecretPattern {
        // SK prefix + 32 hex chars (Twilio API Key SID format)
        name: "Twilio API Key",
        regex: r"\bSK[0-9a-fA-F]{32}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── NPM ──────────────────────────────────────────────────────────────────
    SecretPattern {
        name: "NPM Access Token",
        regex: r"\bnpm_[a-zA-Z0-9]{36}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── PyPI ─────────────────────────────────────────────────────────────────
    SecretPattern {
        name: "PyPI Upload Token",
        regex: r"\bpypi-AgEIcHlwaS5vcmc[\w-]{50,200}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── RubyGems ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "RubyGems API Token",
        regex: r"\brubygems_[a-f0-9]{48}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Databricks ───────────────────────────────────────────────────────────
    SecretPattern {
        name: "Databricks API Token",
        regex: r"\bdapi[a-f0-9]{32}(?:-[0-9])?\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Doppler ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Doppler API Token",
        regex: r"\bdp\.pt\.[a-zA-Z0-9]{43}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Dynatrace ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Dynatrace API Token (dt0c01 format)",
        regex: r"\bdt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Dynatrace Token (generic format)",
        regex: r"\bdt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Grafana ──────────────────────────────────────────────────────────────
    SecretPattern {
        // Grafana API keys are base64 JSON starting with {"k":" → eyJrIjoi
        name: "Grafana API Key (eyJrIjoi prefix)",
        regex: r"\beyJrIjoi[A-Za-z0-9+/]{70,400}={0,3}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Grafana Cloud API Token",
        regex: r"\bglc_[A-Za-z0-9+/]{32,400}={0,3}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Grafana Service Account Token",
        regex: r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── New Relic ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "New Relic User API Key",
        regex: r"\bNRAK-[a-z0-9]{27}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "New Relic Insert Key",
        regex: r"\bNRII-[a-z0-9-]{32}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "New Relic Browser API Token",
        regex: r"\bNRJS-[a-f0-9]{19}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Sentry ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Sentry User Auth Token",
        regex: r"\bsntryu_[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Sentry Org Auth Token",
        regex: r"\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── HashiCorp Vault ──────────────────────────────────────────────────────
    SecretPattern {
        name: "Vault Service Token",
        regex: r"\bhvs\.[\w-]{90,120}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Vault Batch Token",
        regex: r"\bhvb\.[\w-]{138,200}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── HashiCorp Terraform Cloud ────────────────────────────────────────────
    SecretPattern {
        name: "Terraform Cloud API Token",
        regex: r"(?i)\b[a-z0-9]{14}\.atlasv1\.[a-z0-9_-]{60,70}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── PlanetScale ──────────────────────────────────────────────────────────
    SecretPattern {
        name: "PlanetScale API Token",
        regex: r"\bpscale_tkn_[\w=.-]{32,64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "PlanetScale OAuth Token",
        regex: r"\bpscale_oauth_[\w=.-]{32,64}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "PlanetScale Database Password",
        regex: r"\bpscale_pw_[\w=.-]{32,64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Postman ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Postman API Token",
        regex: r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Notion ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Notion Integration Token",
        regex: r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Linear ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Linear API Key",
        regex: r"\blin_api_[a-zA-Z0-9]{40}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Pulumi ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Pulumi API Token",
        regex: r"\bpul-[a-f0-9]{40}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Prefect ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Prefect API Token",
        regex: r"\bpnu_[a-zA-Z0-9]{36}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── ReadMe ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "ReadMe API Token",
        regex: r"\brdme_[a-z0-9]{70}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Scalingo ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Scalingo API Token",
        regex: r"\btk-us-[\w-]{48}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Infracost ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Infracost API Token",
        regex: r"\bico-[a-zA-Z0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── OpenShift ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "OpenShift User Token",
        regex: r"\bsha256~[\w-]{43}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── 1Password ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "1Password Secret Key",
        regex: r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "1Password Service Account Token",
        regex: r"\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Adobe ────────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Adobe Client Secret",
        regex: r"\bp8e-[a-zA-Z0-9]{32}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Age Encryption ───────────────────────────────────────────────────────
    SecretPattern {
        name: "Age Encryption Secret Key",
        regex: r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b",
        kind: PiiKind::PrivateKey,
    },

    // ─── Airtable ─────────────────────────────────────────────────────────────
    SecretPattern {
        // pat + 14 alphanumeric chars + . + 64 hex chars
        name: "Airtable Personal Access Token",
        regex: r"\bpat[a-zA-Z0-9]{14}\.[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Artifactory ──────────────────────────────────────────────────────────
    SecretPattern {
        name: "Artifactory API Key",
        regex: r"\bAKCp[A-Za-z0-9]{69}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "Artifactory Reference Token",
        regex: r"\bcmVmd[A-Za-z0-9]{59}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Atlassian ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Atlassian API Token (ATATT3 format)",
        regex: r"\bATATT3[A-Za-z0-9_=-]{186}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Cloudflare ───────────────────────────────────────────────────────────
    SecretPattern {
        name: "Cloudflare Origin CA Key",
        regex: r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── ClickHouse Cloud ─────────────────────────────────────────────────────
    SecretPattern {
        name: "ClickHouse Cloud API Key",
        regex: r"\b4b1d[A-Za-z0-9]{38}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Clojars ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Clojars API Token",
        regex: r"(?i)\bCLOJARS_[a-z0-9]{60}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Duffel ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Duffel API Token",
        regex: r"\bduffel_(?:test|live)_[a-zA-Z0-9_-]{43}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── EasyPost ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "EasyPost API Token",
        regex: r"\bEZAK[a-zA-Z0-9]{54}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "EasyPost Test API Token",
        regex: r"\bEZTK[a-zA-Z0-9]{54}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Facebook ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Facebook Page / Graph Access Token",
        regex: r"\bEAA[MC][a-zA-Z0-9]{100,}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Fly.io ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Fly.io Access Token",
        regex: r"\b(?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+/]{100,}={0,3}|fm2_[a-zA-Z0-9+/]{100,}={0,3})\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Frame.io ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Frame.io API Token",
        regex: r"\bfio-u-[a-zA-Z0-9_-]{64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Heroku ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Heroku API Key (HRKU prefix)",
        regex: r"\bHRKU-AA[0-9a-zA-Z_-]{58}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── MaxMind ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "MaxMind License Key",
        regex: r"\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Octopus Deploy ───────────────────────────────────────────────────────
    SecretPattern {
        name: "Octopus Deploy API Key",
        regex: r"\bAPI-[A-Z0-9]{26}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Shippo ───────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Shippo API Token",
        regex: r"\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── SettleMint ───────────────────────────────────────────────────────────
    SecretPattern {
        name: "SettleMint Application Access Token",
        regex: r"\bsm_aat_[a-zA-Z0-9]{16}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "SettleMint Personal Access Token",
        regex: r"\bsm_pat_[a-zA-Z0-9]{16}\b",
        kind: PiiKind::GenericApiKey,
    },
    SecretPattern {
        name: "SettleMint Service Access Token",
        regex: r"\bsm_sat_[a-zA-Z0-9]{16}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Typeform ─────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Typeform API Token",
        regex: r"\btfp_[a-z0-9_.-]{59}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Intra42 (42 School) ──────────────────────────────────────────────────
    SecretPattern {
        name: "Intra42 Client Secret",
        regex: r"\bs-s4t2(?:ud|af)-[a-f0-9]{64}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Adafruit IO ──────────────────────────────────────────────────────────
    SecretPattern {
        name: "Adafruit IO Token",
        regex: r"\baio_[a-zA-Z0-9]{28}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Apify ────────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Apify API Token",
        regex: r"\bapify_api_[a-zA-Z0-9-]{36}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Dropbox ──────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Dropbox Short-Lived Token",
        regex: r"\bsl\.[A-Za-z0-9_-]{130,140}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Fleetbase ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Fleetbase Live Token",
        regex: r"\bflb_live_[0-9a-zA-Z]{20}\b",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Cloudinary ───────────────────────────────────────────────────────────
    SecretPattern {
        name: "Cloudinary Credentials URL",
        regex: r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+",
        kind: PiiKind::ConnectionString,
    },

    // ─── Microsoft Teams ──────────────────────────────────────────────────────
    SecretPattern {
        name: "Microsoft Teams Incoming Webhook",
        regex: r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}",
        kind: PiiKind::GenericApiKey,
    },

    // ─── Braintree ────────────────────────────────────────────────────────────
    SecretPattern {
        name: "Braintree Production Access Token",
        regex: r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        kind: PiiKind::GenericApiKey,
    },

    // ─── JSON Web Token (structural) ──────────────────────────────────────────
    SecretPattern {
        // JWTs begin with ey (base64 of {") and have three dot-separated segments.
        // Using base64url charset [A-Za-z0-9_-] for the payload/signature.
        name: "JSON Web Token (JWT)",
        regex: r"\bey[A-Za-z0-9_-]{17,}\.ey[A-Za-z0-9_-]{17,}\.[A-Za-z0-9_-]{10,}={0,2}\b",
        kind: PiiKind::BearerToken,
    },

    // ─── Private Keys (structural) ────────────────────────────────────────────
    SecretPattern {
        // Matches all PEM private key types: RSA, EC, DSA, OPENSSH, PGP, PKCS8
        name: "PEM Private Key Block",
        regex: r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----",
        kind: PiiKind::PrivateKey,
    },

    // ─── Database / Service Connection Strings (structural) ───────────────────
    SecretPattern {
        name: "PostgreSQL Connection String (with credentials)",
        regex: r"postgres(?:ql)?://[^@\s:]{1,}:[^@\s]{1,}@[^\s/]+",
        kind: PiiKind::ConnectionString,
    },
    SecretPattern {
        name: "MySQL Connection String (with credentials)",
        regex: r"mysql(?:2)?://[^@\s:]{1,}:[^@\s]{1,}@[^\s/]+",
        kind: PiiKind::ConnectionString,
    },
    SecretPattern {
        name: "MongoDB Connection String (with credentials)",
        regex: r"mongodb(?:\+srv)?://[^@\s:]{1,}:[^@\s]{1,}@[^\s/]+",
        kind: PiiKind::ConnectionString,
    },
    SecretPattern {
        name: "Redis Connection String (with password)",
        regex: r"redis://:[^@\s]{3,}@[^\s/]+",
        kind: PiiKind::ConnectionString,
    },
    SecretPattern {
        name: "AMQP/RabbitMQ Connection String (with credentials)",
        regex: r"amqps?://[^@\s:]{1,}:[^@\s]{1,}@[^\s/]+",
        kind: PiiKind::ConnectionString,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
//
//   Total patterns: 129
//
//   By PiiKind:
//     AwsKey          :  2  (AWS IAM keys, Bedrock)
//     GithubToken     :  6  (ghp_, gho_, ghs_, ghu_, ghr_, github_pat_)
//     PrivateKey      :  2  (PEM block, Age encryption)
//     BearerToken     :  1  (JWT)
//     ConnectionString:  6  (postgres, mysql, mongodb, redis, amqp, cloudinary)
//     GenericApiKey   :112  (all other prefixed tokens)
//
//   By source:
//     Gitleaks (MIT)                   : ~108 patterns (prefix/structure based only)
//     secrets-patterns-db (Apache 2.0) :  ~12 patterns
//     Derived / deduplicated           :   ~9 patterns
//
//   Explicitly excluded (too noisy for live proxy):
//     - Generic "keyword near random string" patterns (e.g. (?:stripe).{0,40}\b([a-z0-9]{32})\b)
//     - URL-only patterns (AWS endpoints, Firebase domains)
//     - Patterns with very short prefixes that would match common code identifiers
//     - Low-confidence patterns from secrets-patterns-db
// ─────────────────────────────────────────────────────────────────────────────
