//! DNS-01 provider trait and Cloudflare reference impl.

use async_trait::async_trait;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

/// `params` carries provider-specific config (API tokens, zone IDs).
#[async_trait]
pub trait DnsProvider: Send + Sync + 'static {
    async fn upsert_txt(&self, params: &Value, record: &DnsRecord) -> Result<(), String>;
    async fn delete_txt(&self, params: &Value, record: &DnsRecord) -> Result<(), String>;
}

/// No-op — for testbeds that publish DNS records out-of-band.
pub struct NoopDnsProvider;

#[async_trait]
impl DnsProvider for NoopDnsProvider {
    async fn upsert_txt(&self, _: &Value, _: &DnsRecord) -> Result<(), String> {
        Ok(())
    }
    async fn delete_txt(&self, _: &Value, _: &DnsRecord) -> Result<(), String> {
        Ok(())
    }
}

/// `params`: `{ "api_token": "...", "zone_id": "..." }`.
pub struct CloudflareDnsProvider {
    client: reqwest::Client,
}

impl Default for CloudflareDnsProvider {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl CloudflareDnsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    fn token_zone(params: &Value) -> Result<(&str, &str), String> {
        let token = params
            .get("api_token")
            .and_then(Value::as_str)
            .ok_or("missing api_token")?;
        let zone = params
            .get("zone_id")
            .and_then(Value::as_str)
            .ok_or("missing zone_id")?;
        Ok((token, zone))
    }

    async fn find_record(
        &self,
        token: &str,
        zone: &str,
        name: &str,
    ) -> Result<Option<String>, String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={name}"
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .await
            .map_err(|e| e.to_string())?;
        let id = resp
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(id)
    }
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn upsert_txt(&self, params: &Value, record: &DnsRecord) -> Result<(), String> {
        let (token, zone) = Self::token_zone(params)?;
        let body = serde_json::json!({
            "type": "TXT",
            "name": record.name,
            "content": record.value,
            "ttl": record.ttl,
        });
        if let Some(id) = self.find_record(token, zone, &record.name).await? {
            let url = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{id}");
            self.client
                .put(&url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?;
        } else {
            let url = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records");
            self.client
                .post(&url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn delete_txt(&self, params: &Value, record: &DnsRecord) -> Result<(), String> {
        let (token, zone) = Self::token_zone(params)?;
        let Some(id) = self.find_record(token, zone, &record.name).await? else {
            return Ok(());
        };
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{id}");
        self.client
            .delete(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
