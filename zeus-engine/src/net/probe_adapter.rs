//! Adapter pattern — bridges `reqwest` to every probe's minimal HTTP trait.
//!
//! `UnifiedHttpAdapter` implements `JwtHttpClient`, `SamlHttpClient`,
//! `DeviceHttpClient`, `SsrfHttpClient`, and `UebaHttpClient`, eliminating
//! the need for five separate client newtypes in the calling code.

use anyhow::{Result, anyhow};
use std::time::Duration;
use tracing::debug;

use zeus_core::probe::jwt_probe::JwtHttpClient;
use zeus_core::probe::oauth_device_probe::DeviceHttpClient;
use zeus_core::probe::saml_probe::SamlHttpClient;
use zeus_core::probe::ssrf_probe::SsrfHttpClient;
use zeus_core::probe::ueba_probe::UebaHttpClient;

// ─────────────────────────────────────────────────────────────────────────────
// UnifiedHttpAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// A single `reqwest`-backed HTTP adapter that satisfies every probe's
/// minimal HTTP trait requirement.
///
/// # Example
/// ```rust,ignore
/// let adapter = UnifiedHttpAdapter::new(30);
/// jwt_probe.probe(&adapter, "https://api.example.com/resource", &token).await?;
/// ```
#[derive(Debug, Clone)]
pub struct UnifiedHttpAdapter {
    client: reqwest::Client,
}

impl UnifiedHttpAdapter {
    /// Construct a new adapter with the given per-request timeout in seconds.
    pub fn new(timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .use_rustls_tls()
            .danger_accept_invalid_certs(false)
            .user_agent("Mozilla/5.0 (compatible; Zeus/1.0)")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JwtHttpClient impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl JwtHttpClient for UnifiedHttpAdapter {
    /// GET `url` with `Authorization: Bearer <token>`.
    async fn bearer_get(&self, url: &str, token: &str) -> Result<u16> {
        debug!("JWT bearer GET -> {url}");
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| anyhow!("bearer_get to {url}: {e}"))?;
        let status = resp.status().as_u16();
        debug!("JWT bearer GET <- {status}");
        Ok(status)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SamlHttpClient impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SamlHttpClient for UnifiedHttpAdapter {
    /// POST a SAML response to the Assertion Consumer Service URL.
    async fn post_saml(&self, acs_url: &str, saml_response: &str) -> Result<(u16, String)> {
        debug!("SAML POST -> {acs_url}");
        let resp = self
            .client
            .post(acs_url)
            .form(&[("SAMLResponse", saml_response)])
            .send()
            .await
            .map_err(|e| anyhow!("post_saml to {acs_url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("SAML POST <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeviceHttpClient impl  (OAuth 2.0 Device Authorization)
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl DeviceHttpClient for UnifiedHttpAdapter {
    /// POST URL-encoded form parameters to `url`.
    async fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<(u16, String)> {
        debug!("Device POST form -> {url}");
        let resp = self
            .client
            .post(url)
            .form(params)
            .send()
            .await
            .map_err(|e| anyhow!("post_form to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("Device POST form <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsrfHttpClient impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SsrfHttpClient for UnifiedHttpAdapter {
    /// GET `endpoint` with extra (name, value) headers.
    async fn get_with_headers(
        &self,
        endpoint: &str,
        headers: &[(&str, &str)],
    ) -> Result<(u16, String)> {
        debug!("SSRF GET (headers) -> {endpoint}");
        let mut req = self.client.get(endpoint);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("get_with_headers to {endpoint}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("SSRF GET (headers) <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }

    /// GET `endpoint` with a single query parameter appended.
    async fn get_with_param(
        &self,
        endpoint: &str,
        param: &str,
        value: &str,
    ) -> Result<(u16, String)> {
        debug!("SSRF GET (param) -> {endpoint}?{param}=...");
        let resp = self
            .client
            .get(endpoint)
            .query(&[(param, value)])
            .send()
            .await
            .map_err(|e| anyhow!("get_with_param to {endpoint}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("SSRF GET (param) <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UebaHttpClient impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl UebaHttpClient for UnifiedHttpAdapter {
    /// GET `url`, returning `(status_code, body)`.
    async fn get(&self, url: &str) -> Result<(u16, String)> {
        debug!("UEBA GET -> {url}");
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("get to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("UEBA GET <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }

    /// POST URL-encoded form fields to `url`.
    async fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<(u16, String)> {
        debug!("UEBA POST form -> {url}");
        let resp = self
            .client
            .post(url)
            .form(fields)
            .send()
            .await
            .map_err(|e| anyhow!("ueba post_form to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("UEBA POST form <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }
}
