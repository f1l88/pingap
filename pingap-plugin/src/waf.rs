use super::{get_hash_key, get_plugin_factory, get_str_conf, Error};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::{borrow::Cow, fs, path::Path, sync::Arc};
use tracing::debug;
use modsecurity::{ModSecurity, Rules};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Результат проверки WAF
#[derive(Debug, Clone)]
pub struct WafCheckResult {
    pub allowed: bool,
    pub matched_rule: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub reason: String,
    pub rule_id: u32,
}

/// Встроенный движок WAF
pub struct Engine {
    ms: ModSecurity,
    rules: Rules,
}

impl Engine {
    /// Загружает правила ModSecurity из файла
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let rules_text = fs::read_to_string(&path).map_err(|e| Error::Invalid {
            category: "waf".to_string(),
            message: format!("Failed to read rules file: {e}"),
        })?;

        let ms = ModSecurity::default();
        let mut rules = Rules::new();
        rules.add_plain(&rules_text).map_err(|e| Error::Invalid {
            category: "waf".to_string(),
            message: format!("Failed to add rules: {e}"),
        })?;

        println!("✅ ModSecurity rules loaded: {}", path.as_ref().display());
        Ok(Self { ms, rules })
    }

    /// Проверка запроса
    pub fn check_detailed(&self, headers: &pingora::http::HMap, uri: &str) -> WafCheckResult {
        let mut tx = match self.ms.transaction_builder().with_rules(&self.rules).build() {
            Ok(tx) => tx,
            Err(e) => {
                return WafCheckResult {
                    allowed: true,
                    matched_rule: None,
                    header_name: None,
                    header_value: None,
                    reason: format!("Transaction build error: {e}"),
                    rule_id: 0,
                }
            }
        };

        let method = "GET"; // default
        if let Err(e) = tx.process_uri(uri, method, "1.1") {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_uri error: {e}"),
                rule_id: 0,
            };
        }

        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                if let Err(e) = tx.add_request_header(&name.to_string(), v) {
                    eprintln!("Failed to add header {}: {}", name, e);
                }
            }
        }

        if let Err(e) = tx.process_request_headers() {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_request_headers error: {e}"),
                rule_id: 0,
            };
        }

        if let Some(intervention) = tx.intervention() {
            let status = intervention.status();
            let msg = intervention.log().map_or_else(
                || format!("Blocked by ModSecurity with status {}", status),
                |log| log.to_string(),
            );

            return WafCheckResult {
                allowed: false,
                matched_rule: Some(msg.clone()),
                header_name: None,
                header_value: None,
                reason: format!("Blocked by ModSecurity: {}", msg),
                rule_id: status as u32,
            };
        }

        WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: "Allowed by ModSecurity".into(),
            rule_id: 0,
        }
    }
}

/// Плагин Pingap
pub struct Waf {
    plugin_step: PluginStep,
    engine: Engine,
    forbidden_resp: HttpResponse,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Waf {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let rules_path = get_str_conf(value, "rules_path");
        if rules_path.is_empty() {
            return Err(Error::Invalid {
                category: "config".to_string(),
                message: "rules_path is required".to_string(),
            });
        }

        let engine = Engine::load(&rules_path)?;

        let msg = get_str_conf(value, "message");
        let forbidden_resp = HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from(if msg.is_empty() { "Blocked by WAF" } else { "no block" }),
            ..Default::default()
        };

        Ok(Self {
            hash_value,
            plugin_step: PluginStep::Request,
            engine,
            forbidden_resp,
        })
    }
}

impl Waf {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "WAF plugin initialized");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Waf {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        let uri = session.req_header().uri.to_string();
        let headers = session.req_header().headers.clone();

        let res = self.engine.check_detailed(&headers, &uri);

        if !res.allowed {
            let mut resp = self.forbidden_resp.clone();
            resp.body = Bytes::from(format!("Blocked: {}", res.reason));
            return Ok(RequestPluginResult::Respond(resp));
        }

        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("waf", |params| {
        Ok(Arc::new(Waf::new(params)?))
    });
}
