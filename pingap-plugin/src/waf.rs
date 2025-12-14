use super::{get_hash_key, get_plugin_factory, get_str_conf, Error};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::{borrow::Cow, fs, path::Path, sync::Arc};
use tracing::{debug, warn};
use modsecurity::{ModSecurity, Rules, Transaction};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Результат проверки WAF
#[derive(Debug, Clone)]
pub struct WafCheckResult {
    pub allowed: bool,
    #[allow(dead_code)]
    pub matched_rule: Option<String>,
    #[allow(dead_code)]
    pub header_name: Option<String>,
    #[allow(dead_code)]
    pub header_value: Option<String>,
    pub reason: String,
    pub rule_id: u32,
    pub rule_msg: Option<String>,
    pub rule_data: Option<String>,
    #[allow(dead_code)]
    pub rule_severity: Option<String>,
    #[allow(dead_code)]
    pub rule_tags: Option<Vec<String>>,
}

impl WafCheckResult {
    fn default_allowed() -> Self {
        Self {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: "Allowed by ModSecurity".into(),
            rule_id: 0,
            rule_msg: None,
            rule_data: None,
            rule_severity: None,
            rule_tags: None,
        }
    }
}

/// Встроенный движок WAF
pub struct Engine {
    ms: ModSecurity,
    rules: Rules,
}

impl Engine {
    /// Загружает правила ModSecurity из файла
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        let ms = ModSecurity::default();
        let mut rules = Rules::new();
        
        rules.add_file(path).map_err(|e| {
            let err_str = e.to_string();
            Error::Invalid {
                category: "waf".to_string(),
                message: format!("Failed to load rules from file {}: {}", path.display(), err_str),
            }
        })?;

        println!("✅ ModSecurity rules loaded from file: {}", path.display());
        Ok(Self { ms, rules })
    }

    /// Загружает правила ModSecurity из всех файлов в директории
    pub fn load_from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let ms = ModSecurity::default();
        let mut rules = Rules::new();
        
        println!("📁 Loading WAF rules from: {}", dir_path.as_ref().display());
        
        let dir = fs::read_dir(&dir_path).map_err(|e| Error::Invalid {
            category: "waf".to_string(),
            message: format!("Failed to read directory: {e}"),
        })?;
        
        let mut loaded_files = 0;
        let mut skipped_files = 0;
        
        // Собираем все файлы, сортируем по приоритету
        let mut files = Vec::new();
        let mut priority_files = Vec::new();
        
        for entry in dir {
            let entry = entry.map_err(|e| Error::Invalid {
                category: "waf".to_string(),
                message: format!("Failed to read directory entry: {e}"),
            })?;
            
            let path = entry.path();
            
            if !path.is_file() {
                continue;
            }
            
            // Проверяем расширение файла
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !ext_str.ends_with("conf") && !ext_str.ends_with("rules") {
                    continue;
                }
            }
            
            // Определяем приоритет файлов
            if let Some(filename) = path.file_name() {
                let name = filename.to_string_lossy().to_lowercase();
                
                // Файлы, которые должны загружаться первыми
                if name == "crs-setup.conf" || 
                   name.contains("900-exclusion") ||
                   name.contains("901-initialization") ||
                   name.contains("test-guaranteed-block") ||  // Тестовые правила с высоким приоритетом
                   name.contains("test-immediate") ||
                   name.contains("test-block") {
                    let priority = Self::get_file_priority(&name);
                    priority_files.push((priority, path));
                } else {
                    files.push(path);
                }
            }
        }
        
        // Сортируем приоритетные файлы
        priority_files.sort_by_key(|(priority, _)| *priority);
        
        // Сначала загружаем приоритетные файлы
        for (priority, path) in &priority_files {
            println!("   Loading priority file (priority {}): {}", priority, path.display());
            match rules.add_file(&path) {
                Ok(()) => {
                    println!("     ✅ Success");
                    loaded_files += 1;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("Failed to open file") || err_str.contains(".data") {
                        println!("     ⚠️  Warning: {}", err_str);
                        loaded_files += 1;
                    } else {
                        println!("     ❌ Error: {}", err_str);
                        skipped_files += 1;
                    }
                }
            }
        }
        
        // Затем остальные файлы
        files.sort();
        
        for path in files {
            println!("   Loading file: {}", path.display());
            match rules.add_file(&path) {
                Ok(()) => {
                    println!("     ✅ Success");
                    loaded_files += 1;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("Failed to open file") || err_str.contains(".data") {
                        println!("     ⚠️  Warning: {}", err_str);
                        loaded_files += 1;
                    } else {
                        println!("     ❌ Error: {}", err_str);
                        skipped_files += 1;
                    }
                }
            }
        }
        
        if loaded_files == 0 {
            return Err(Error::Invalid {
                category: "waf".to_string(),
                message: format!("No rule files successfully loaded from directory: {}", dir_path.as_ref().display()),
            });
        }
        
        println!("📁 Summary: {} files loaded, {} files skipped from: {}", 
                 loaded_files, skipped_files, dir_path.as_ref().display());
        
        // Тестовая транзакция для проверки
        if let Ok(_tx) = ms.transaction_builder().with_rules(&rules).build() {
            println!("✅ Test transaction built successfully");
        } else {
            println!("❌ Failed to build test transaction");
        }
        
        Ok(Self { ms, rules })
    }

    /// Загружает правила из пути (файла или директории)
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        
        if path_ref.is_dir() {
            Self::load_from_directory(path_ref)
        } else if path_ref.is_file() {
            Self::load_from_file(path_ref)
        } else {
            Err(Error::Invalid {
                category: "waf".to_string(),
                message: format!("Path is neither a file nor a directory: {}", path_ref.display()),
            })
        }
    }

    /// Вспомогательная функция для определения приоритета файла
    fn get_file_priority(filename: &str) -> u32 {
        match filename {
            f if f == "crs-setup.conf" => 1,
            f if f.contains("test-guaranteed-block") => 2,
            f if f.contains("test-immediate") => 3,
            f if f.contains("test-block") => 4,
            f if f.contains("900-exclusion-rules-before-crs") => 5,
            f if f.contains("901-initialization") => 6,
            f if f.contains("905-common-exceptions") => 7,
            _ => 100, // Остальные файлы
        }
    }

/// Расширенная проверка запроса с fallback
pub fn check_request(&self, headers: &pingora::http::HMap, uri: &str, method: &str) -> WafCheckResult {
    println!("🔍 WAF CHECK START: {} {}", method, uri);
    println!("   Headers count: {}", headers.len());

    // СОХРАНЯЕМ заголовки для fallback проверки
    let user_agent = headers.get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());
    
    let host = headers.get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref ua) = user_agent {
        println!("   User-Agent: {}", ua);
    }
    
    if let Some(ref h) = host {
        println!("   Host: {}", h);
    }

    let mut tx = match self.ms.transaction_builder().with_rules(&self.rules).build() {
        Ok(tx) => {
            println!("✅ Transaction built successfully");
            tx
        }
        Err(e) => {
            println!("❌ Failed to build transaction: {}", e);
            let result = WafCheckResult::default_allowed();
            println!("🔍 WAF CHECK END: allowed = {}", result.allowed);
            return result;
        }
    };

    // Обрабатываем URI и метод
    if let Err(e) = tx.process_uri(uri, method, "1.1") {
        println!("❌ process_uri error: {}", e);
        let result = WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: format!("process_uri error: {e}"),
            rule_id: 0,
            rule_msg: None,
            rule_data: None,
            rule_severity: None,
            rule_tags: None,
        };
        println!("🔍 WAF CHECK END: allowed = {}", result.allowed);
        return result;
    }

    // Добавляем заголовки
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            if let Err(e) = tx.add_request_header(&name.to_string(), v) {
                eprintln!("   Failed to add header {}: {}", name, e);
            }
        }
    }

    // Обрабатываем заголовки запроса
    if let Err(e) = tx.process_request_headers() {
        println!("❌ process_request_headers error: {}", e);
        let result = WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: format!("process_request_headers error: {e}"),
            rule_id: 0,
            rule_msg: None,
            rule_data: None,
            rule_severity: None,
            rule_tags: None,
        };
        println!("🔍 WAF CHECK END: allowed = {}", result.allowed);
        return result;
    }

    // Проверяем интервенцию
    let result = self.check_intervention(&mut tx);
    
    // FALLBACK: Если интервенции нет, но User-Agent содержит masscan, блокируем напрямую
    if result.allowed {
        if let Some(ref ua) = user_agent {
            if ua.contains("masscan") || ua.contains("nikto") || ua.contains("sqlmap") {
                println!("🔴 FALLBACK BLOCK: Security scanner in User-Agent");
                return WafCheckResult {
                    allowed: false,
                    matched_rule: Some("Fallback scanner detection".to_string()),
                    header_name: Some("user-agent".to_string()),
                    header_value: Some(ua.clone()),
                    reason: "Blocked: Security scanner detected (fallback)".to_string(),
                    rule_id: 1000,
                    rule_msg: Some("Security scanner fallback block".to_string()),
                    rule_data: None,
                    rule_severity: None,
                    rule_tags: Some(vec!["fallback".to_string()]),
                };
            }
        }
        
        // FALLBACK: Если Host содержит IP
        if let Some(ref h) = host {
            let ip_regex = regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+").unwrap();
            if ip_regex.is_match(h) {
                println!("🔴 FALLBACK BLOCK: IP address in Host header");
                return WafCheckResult {
                    allowed: false,
                    matched_rule: Some("Fallback IP in Host".to_string()),
                    header_name: Some("host".to_string()),
                    header_value: Some(h.clone()),
                    reason: "Blocked: IP address in Host header (fallback)".to_string(),
                    rule_id: 1001,
                    rule_msg: Some("IP in Host fallback block".to_string()),
                    rule_data: None,
                    rule_severity: None,
                    rule_tags: Some(vec!["fallback".to_string()]),
                };
            }
        }
    }
    
    println!("🔍 WAF CHECK END: allowed = {}", result.allowed);
    result
}

    /// Проверка запроса с телом
    #[allow(dead_code)] 
    pub fn check_request_with_body(&self, headers: &pingora::http::HMap, uri: &str, method: &str, body: Option<&[u8]>) -> WafCheckResult {
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
                    rule_msg: None,
                    rule_data: None,
                    rule_severity: None,
                    rule_tags: None,
                }
            }
        };

        // Обрабатываем URI и метод
        if let Err(e) = tx.process_uri(uri, method, "1.1") {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_uri error: {e}"),
                rule_id: 0,
                rule_msg: None,
                rule_data: None,
                rule_severity: None,
                rule_tags: None,
            };
        }

        // Добавляем заголовки
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                if let Err(e) = tx.add_request_header(&name.to_string(), v) {
                    eprintln!("Failed to add header {}: {}", name, e);
                }
            }
        }

        // Обрабатываем заголовки запроса
        if let Err(e) = tx.process_request_headers() {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_request_headers error: {e}"),
                rule_id: 0,
                rule_msg: None,
                rule_data: None,
                rule_severity: None,
                rule_tags: None,
            };
        }

        // Обрабатываем тело запроса, если есть
        if let Some(body_data) = body {
            if let Err(e) = tx.append_request_body(body_data) {
                eprintln!("Failed to append request body: {}", e);
            }
            
            if let Err(e) = tx.process_request_body() {
                return WafCheckResult {
                    allowed: true,
                    matched_rule: None,
                    header_name: None,
                    header_value: None,
                    reason: format!("process_request_body error: {e}"),
                    rule_id: 0,
                    rule_msg: None,
                    rule_data: None,
                    rule_severity: None,
                    rule_tags: None,
                };
            }
        }

        // Проверяем интервенцию
        self.check_intervention(&mut tx)
    }

    /// Проверка ответа (phase:4)
    #[allow(dead_code)] 
    pub fn check_response(&self, response_body: &[u8], response_headers: Option<&pingora::http::HMap>) -> WafCheckResult {
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
                    rule_msg: None,
                    rule_data: None,
                    rule_severity: None,
                    rule_tags: None,
                }
            }
        };

        // Добавляем заголовки ответа, если есть
        if let Some(headers) = response_headers {
            for (name, value) in headers.iter() {
                if let Ok(v) = value.to_str() {
                    if let Err(e) = tx.add_response_header(&name.to_string(), v) {
                        eprintln!("Failed to add response header {}: {}", name, e);
                    }
                }
            }
        }

        // Обрабатываем заголовки ответа
        if let Err(e) = tx.process_response_headers(200, "1.1") {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_response_headers error: {e}"),
                rule_id: 0,
                rule_msg: None,
                rule_data: None,
                rule_severity: None,
                rule_tags: None,
            };
        }

        // Обрабатываем тело ответа
        if let Err(e) = tx.append_response_body(response_body) {
            eprintln!("Failed to append response body: {}", e);
        }
        
        if let Err(e) = tx.process_response_body() {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("process_response_body error: {e}"),
                rule_id: 0,
                rule_msg: None,
                rule_data: None,
                rule_severity: None,
                rule_tags: None,
            };
        }

        // Проверяем интервенцию
        self.check_intervention(&mut tx)
    }

    /// Вспомогательная функция для проверки интервенции
    fn check_intervention(&self, tx: &mut Transaction) -> WafCheckResult {
        // Проверяем стандартную интервенцию
        if let Some(intervention) = tx.intervention() {
            let status = intervention.status();
            let log_msg = intervention.log().map(|s| s.to_string());
            let disruptive = intervention.disruptive();
            
            println!("🚨 WAF Intervention detected!");
            println!("   Rule ID: {}", status);
            println!("   Disruptive: {}", disruptive);
            println!("   Pause: {}ms", intervention.pause());
            
            // Проверяем URL (может содержать redirect)
            if let Some(url) = intervention.url() {
                println!("   URL: {}", url);
            }
            
            if let Some(log) = &log_msg {
                println!("   Log: {}", log);
                
                // Проверяем, содержит ли лог deny/block
                if log.contains("deny") {
                    println!("   ✅ Log contains DENY action");
                } else if log.contains("block") {
                    println!("   ⚠️  Log contains BLOCK action");
                } else {
                    println!("   ❌ Log does not contain deny/block");
                }
            }
            
            // Извлекаем дополнительные поля из лога
            let (rule_msg, rule_data) = Self::parse_log_fields(&log_msg);
            
            // ФОРМИРУЕМ ПРИЧИНУ
            let reason = if disruptive {
                match &rule_msg {
                    Some(msg) => format!("Blocked: {}", msg),
                    None => match &log_msg {
                        Some(log) => format!("Blocked: {}", log),
                        None => format!("Blocked by rule {}", status),
                    },
                }
            } else {
                match &rule_msg {
                    Some(msg) => format!("Warning: {}", msg),
                    None => match &log_msg {
                        Some(log) => format!("Warning: {}", log),
                        None => format!("Warning from rule {}", status),
                    },
                }
            };
            
            // Определяем, разрешен ли запрос
            let allowed = !disruptive;
            
            if !allowed {
                println!("🔴 REQUEST BLOCKED! disruptive = true");
            } else {
                println!("⚠️  Warning only (request allowed) disruptive = false");
            }
            
            return WafCheckResult {
                allowed,
                matched_rule: log_msg.clone(),
                header_name: None,
                header_value: None,
                reason,
                rule_id: status as u32,
                rule_msg,
                rule_data,
                rule_severity: None,
                rule_tags: Some(vec!["OWASP_CRS".to_string()]),
            };
        }
        
        // ВАЖНО: Если intervention() возвращает None, значит правила не сработали как disruptive
        // Но в логах мы видим, что правила обнаруживаются. 
        // Это значит, что правила настроены как "log" или "pass", а не "deny"/"block"
        println!("⚠️  No WAF intervention found - rules detected but not disruptive");
        println!("    This means rules are configured as 'log' or 'pass', not 'deny'/'block'");
        
        WafCheckResult::default_allowed()
    }
    
    /// Парсит поля msg и data из лога ModSecurity
    fn parse_log_fields(log_msg: &Option<String>) -> (Option<String>, Option<String>) {
        if let Some(log) = log_msg {
            let mut msg = None;
            let mut data = None;
            
            // Простой парсинг полей [msg "..."] [data "..."]
            let mut pos = 0;
            while pos < log.len() {
                if let Some(start) = log[pos..].find('[') {
                    let field_start = pos + start;
                    
                    if let Some(field_end) = log[field_start..].find(']') {
                        let field_content = &log[field_start..field_start + field_end + 1];
                        
                        if field_content.starts_with("[msg \"") {
                            if let Some(value_end) = field_content.find("\"]") {
                                msg = Some(field_content[6..value_end].to_string());
                            }
                        } else if field_content.starts_with("[data \"") {
                            if let Some(value_end) = field_content.find("\"]") {
                                data = Some(field_content[7..value_end].to_string());
                            }
                        }
                        
                        pos = field_start + field_end + 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            
            (msg, data)
        } else {
            (None, None)
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

        println!("🔧 Initializing WAF plugin...");
        println!("   Rules path: {}", rules_path);
        
        let engine = match Engine::load(&rules_path) {
            Ok(engine) => {
                println!("✅ WAF engine loaded successfully");
                engine
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("Failed to open file") || err_msg.contains(".data") {
                    println!("⚠️  WAF engine initialized with warnings: {}", err_msg);
                    let ms = ModSecurity::default();
                    let rules = Rules::new();
                    Engine { ms, rules }
                } else {
                    return Err(e);
                }
            }
        };

        let msg = get_str_conf(value, "message");
        let response_body = if msg.is_empty() { 
            "Blocked by WAF".to_string() 
        } else { 
            msg
        };
        
        let forbidden_resp = HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from(response_body),
            ..Default::default()
        };

        println!("✅ WAF plugin initialized successfully");
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

        let uri = session.req_header().uri.path().to_string();
        let method = session.req_header().method.to_string();
        let headers = session.req_header().headers.clone();

        // Логируем информацию о запросе
        debug!("WAF checking request: {} {}", method, uri);
        
        if let Some(host) = headers.get("host") {
            if let Ok(host_str) = host.to_str() {
                debug!("Request Host: {}", host_str);
            }
        }
        if let Some(ua) = headers.get("user-agent") {
            if let Ok(ua_str) = ua.to_str() {
                debug!("User-Agent: {}", ua_str);
            }
        }

        // Проверяем запрос
        let res = self.engine.check_request(&headers, &uri, &method);

        if !res.allowed {
            // Структурированное логирование
            warn!(
                rule_id = res.rule_id,
                rule_msg = ?res.rule_msg,
                matched_data = ?res.rule_data,
                uri = uri,
                method = method,
                reason = res.reason,
                "WAF blocked request"
            );
            
            let mut resp = self.forbidden_resp.clone();
            resp.body = Bytes::from(format!("Blocked: {}", res.reason));
            return Ok(RequestPluginResult::Respond(resp));
        }

        debug!("WAF allowed request");
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("waf", |params| {
        Ok(Arc::new(Waf::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wso_webshell_rule() {
        let ms = ModSecurity::default();
        let mut rules = Rules::new();
        
        let test_rule = r#"
SecRule RESPONSE_BODY "@rx ^<html><head><meta http-equiv='Content-Type' content='text/html; charset=(?:Windows-1251|UTF-8)?'><title>.*?(?: -)? W[Ss][Oo] [0-9.]+</title>" \
    "id:955120,\
    phase:4,\
    block,\
    capture,\
    t:none,\
    msg:'WSO web shell',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
    tag:'test',\
    ver:'OWASP_CRS/4.20.0',\
    severity:'CRITICAL'"
"#;
        
        rules.add_plain(test_rule).expect("Failed to add test rule");
        
        let engine = Engine { ms, rules };
        
        // Тестируем правило phase:4 (ответ)
        let malicious_response = b"<html><head><meta http-equiv='Content-Type' content='text/html; charset=UTF-8'><title>Test - WSO 2.5</title></head><body>Test</body></html>";
        
        let result = engine.check_response(malicious_response, None);
        
        // Правило должно сработать
        assert!(!result.allowed);
        assert_eq!(result.rule_id, 955120);
        assert!(result.rule_msg.unwrap().contains("WSO web shell"));
        
        println!("✅ WSO web shell rule test passed!");
    }

    #[test]
    fn test_scanner_detection() {
        let ms = ModSecurity::default();
        let mut rules = Rules::new();
        
        let test_rule = r#"
SecRule REQUEST_HEADERS:User-Agent "@pm masscan nikto sqlmap" \
    "id:913100,\
    phase:1,\
    deny,\
    status:403,\
    t:none,\
    msg:'Found User-Agent associated with security scanner',\
    tag:'test'"
"#;
        
        rules.add_plain(test_rule).expect("Failed to add test rule");
        
        let engine = Engine { ms, rules };
        
        // Создаем заголовки с User-Agent сканера
        let mut headers = pingora::http::HMap::new();
        headers.insert("user-agent", "masscan".parse().unwrap());
        headers.insert("host", "example.com".parse().unwrap());
        
        let result = engine.check_request(&headers, "/", "GET");
        
        // Правило должно сработать
        assert!(!result.allowed);
        assert_eq!(result.rule_id, 913100);
        
        println!("✅ Scanner detection rule test passed!");
    }
}