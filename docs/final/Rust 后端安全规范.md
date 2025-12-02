# Rust 后端安全规范

---

## 目录

1. [核心原则](#1-核心原则)
2. [密码处理](#2-密码处理)
3. [JWT 认证](#3-jwt-认证)
4. [SQL 注入防护](#4-sql-注入防护)
5. [输入验证与清理](#5-输入验证与清理)
6. [敏感数据保护](#6-敏感数据保护)
7. [速率限制与防暴力破解](#7-速率限制与防暴力破解)
8. [安全响应头配置](#8-安全响应头配置)
9. [依赖配置参考](#9-依赖配置参考)
10. [团队约定清单](#10-团队约定清单)
11. [快速参考卡片](#11-快速参考卡片)

---

## 1. 核心原则

| 原则 | 说明 | 实践 |
|------|------|------|
| **纵深防御** | 多层安全机制，单点失效不致灾 | 输入验证 + 参数化查询 + 输出编码 |
| **最小权限** | 只授予必要的权限 | 数据库账号只读/写分离，JWT 细粒度 scope |
| **安全默认** | 默认配置应是安全的 | 默认拒绝，显式允许 |
| **失败安全** | 出错时倾向于拒绝而非允许 | 认证失败返回通用错误，不泄露细节 |

**一句话总结**：不信任任何输入，保护所有敏感数据，记录所有安全事件。

---

## 2. 密码处理

### 2.1 基本实现

使用 `secrecy` 包装敏感数据，`argon2` 进行哈希。

```rust
// src/auth/password.rs
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use secrecy::{ExposeSecret, SecretString};

/// 哈希密码（用于注册/修改密码）
pub fn hash_password(password: &SecretString) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();  // 使用 Argon2id 变体
    let hash = argon2.hash_password(password.expose_secret().as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// 验证密码（用于登录）
pub fn verify_password(password: &SecretString, hash: &str) -> bool {
    PasswordHash::new(hash)
        .and_then(|h| Argon2::default().verify_password(password.expose_secret().as_bytes(), &h))
        .is_ok()
}
```

### 2.2 密码强度验证

```rust
// src/auth/validation.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("密码长度必须在 8-128 字符之间，当前: {0}")]
    InvalidLength(usize),
    
    #[error("密码必须包含大写字母")]
    MissingUppercase,
    
    #[error("密码必须包含小写字母")]
    MissingLowercase,
    
    #[error("密码必须包含数字")]
    MissingDigit,
    
    #[error("密码必须包含特殊字符")]
    MissingSpecial,
}

pub fn validate_password_strength(password: &str) -> Result<(), PasswordError> {
    let len = password.len();
    
    if !(8..=128).contains(&len) {
        return Err(PasswordError::InvalidLength(len));
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(PasswordError::MissingUppercase);
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(PasswordError::MissingLowercase);
    }
    
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(PasswordError::MissingDigit);
    }
    
    if !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
        return Err(PasswordError::MissingSpecial);
    }
    
    Ok(())
}
```

### 2.3 在 Handler 中使用

```rust
// src/api/handlers/auth.rs
use secrecy::SecretString;
use anyhow::{Context, Result, bail};

pub async fn register(req: RegisterReq) -> Result<Json<UserResponse>> {
    // 包装为 SecretString，防止意外泄露
    let password = SecretString::from(req.password);
    
    // 验证密码强度
    validate_password_strength(password.expose_secret())
        .context("密码强度不符合要求")?;
    
    // 哈希存储
    let password_hash = hash_password(&password)
        .context("密码哈希失败")?;
    
    let user = db::create_user(&req.email, &password_hash)
        .await
        .context("创建用户失败")?;
    
    Ok(Json(UserResponse::from(user)))
}
```

### 2.4 密码处理规范要点

| 规则 | 说明 |
|------|------|
| 必须使用 `SecretString` | 防止密码在日志、Debug 输出中泄露 |
| 必须使用 Argon2id | 当前最推荐的密码哈希算法 |
| 密码长度 8-128 字符 | 过短不安全，过长可能被用于 DoS |
| 禁止明文存储 | 数据库只存哈希值 |
| 禁止可逆加密 | 只能单向哈希，不可解密 |

---

## 3. JWT 认证

### 3.1 Claims 结构定义

```rust
// src/auth/jwt.rs
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Token 已过期")]
    Expired,
    
    #[error("Token 格式无效")]
    InvalidFormat,
    
    #[error("Token 签名验证失败")]
    InvalidSignature,
    
    #[error("Token 生成失败: {0}")]
    CreationFailed(#[from] jsonwebtoken::errors::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// 用户唯一标识
    pub sub: String,
    /// 过期时间 (Unix timestamp)
    pub exp: i64,
    /// 签发时间
    pub iat: i64,
    /// 用户角色
    pub role: String,
    /// 权限范围
    pub scopes: Vec<String>,
    /// Token ID（用于吊销）
    pub jti: String,
}
```

### 3.2 Token 生成与验证

```rust
use uuid::Uuid;

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

impl JwtManager {
    /// 创建 JWT 管理器
    /// secret 必须至少 32 字符
    pub fn new(secret: &[u8]) -> Result<Self, JwtError> {
        if secret.len() < 32 {
            panic!("JWT secret 必须至少 32 字符");
        }
        
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            access_token_ttl: Duration::minutes(30),
            refresh_token_ttl: Duration::days(7),
        })
    }
    
    /// 生成 Access Token
    pub fn create_access_token(
        &self,
        user_id: &str,
        role: &str,
        scopes: Vec<String>,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.into(),
            exp: (now + self.access_token_ttl).timestamp(),
            iat: now.timestamp(),
            role: role.into(),
            scopes,
            jti: Uuid::new_v4().to_string(),
        };
        
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(JwtError::CreationFailed)
    }
    
    /// 验证并解析 Token
    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0;  // 不允许时间偏差
        
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => JwtError::InvalidSignature,
                _ => JwtError::InvalidFormat,
            })
    }
}
```

### 3.3 Middleware 集成 (Axum)

```rust
// src/api/middleware/auth.rs
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let jwt_manager = request
        .extensions()
        .get::<JwtManager>()
        .expect("JwtManager not configured");
    
    let claims = jwt_manager
        .verify_token(token)
        .map_err(|e| {
            tracing::warn!(error = ?e, "Token 验证失败");
            StatusCode::UNAUTHORIZED
        })?;
    
    // 将 claims 注入到请求扩展中
    request.extensions_mut().insert(claims);
    
    Ok(next.run(request).await)
}
```

### 3.4 JWT 规范要点

| 规则 | 说明 |
|------|------|
| 密钥长度 ≥ 32 字符 | 防止暴力破解 |
| Access Token ≤ 30 分钟 | 短期 Token 减少泄露风险 |
| Refresh Token ≤ 7 天 | 配合滑动过期使用 |
| 必须验证 `exp` 字段 | 防止过期 Token 被使用 |
| 包含 `jti` 字段 | 支持 Token 吊销（黑名单机制） |
| 禁止在 Token 中存储敏感数据 | Token 是 Base64 编码，非加密 |

---

## 4. SQL 注入防护

### 4.1 参数化查询基础

```rust
// src/db/user.rs
use sqlx::PgPool;

// ❌ 危险：字符串拼接
async fn get_user_unsafe(pool: &PgPool, name: &str) -> Result<User, sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query_as(&query).fetch_one(pool).await
}

// ✅ 安全：参数化查询（编译时检查）
async fn get_user_safe(pool: &PgPool, name: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE name = $1", name)
        .fetch_optional(pool)
        .await
}
```

### 4.2 动态查询条件

```rust
// src/db/user.rs
use sqlx::{PgPool, QueryBuilder, Postgres};

#[derive(Debug)]
pub struct UserFilter {
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

// ✅ 安全：使用 QueryBuilder 构建动态查询
pub async fn search_users(
    pool: &PgPool,
    filter: &UserFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>, sqlx::Error> {
    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT id, name, email, role, is_active, created_at FROM users WHERE 1=1"
    );
    
    if let Some(ref name) = filter.name {
        builder.push(" AND name ILIKE ");
        builder.push_bind(format!("%{}%", name));
    }
    
    if let Some(ref email) = filter.email {
        builder.push(" AND email = ");
        builder.push_bind(email);
    }
    
    if let Some(ref role) = filter.role {
        builder.push(" AND role = ");
        builder.push_bind(role);
    }
    
    if let Some(is_active) = filter.is_active {
        builder.push(" AND is_active = ");
        builder.push_bind(is_active);
    }
    
    // 分页限制
    let safe_limit = limit.min(100).max(1);  // 限制 1-100
    builder.push(" LIMIT ");
    builder.push_bind(safe_limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset.max(0));
    
    builder
        .build_query_as::<User>()
        .fetch_all(pool)
        .await
}
```

### 4.3 可选参数模式

```rust
// ✅ 安全：使用 NULL 判断处理可选参数
pub async fn find_users(
    pool: &PgPool,
    keyword: Option<&str>,
    role: Option<&str>,
) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users
        WHERE ($1::text IS NULL OR name ILIKE '%' || $1 || '%')
          AND ($2::text IS NULL OR role = $2)
        ORDER BY created_at DESC
        LIMIT 100
        "#,
        keyword,
        role
    )
    .fetch_all(pool)
    .await
}
```

### 4.4 SQL 安全规范要点

| 规则 | 说明 |
|------|------|
| 100% 参数化查询 | 绝对禁止字符串拼接 SQL |
| 优先使用 `query_as!` 宏 | 编译时类型检查 |
| 动态查询用 `QueryBuilder` | 安全构建动态条件 |
| 分页必须有上限 | `LIMIT` 最大 100，防止全表扫描 |
| 使用类型化参数 | `$1::text` 显式声明类型 |
| 最小权限数据库账号 | 应用账号禁止 `DROP`、`ALTER` 权限 |

---

## 5. 输入验证与清理

### 5.1 使用 validator 进行结构化验证

```rust
// src/api/dto/user.rs
use validator::Validate;
use serde::Deserialize;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserReq {
    #[validate(length(min = 2, max = 50, message = "用户名长度必须在 2-50 之间"))]
    pub name: String,
    
    #[validate(email(message = "邮箱格式不正确"))]
    pub email: String,
    
    #[validate(length(min = 8, max = 128, message = "密码长度必须在 8-128 之间"))]
    pub password: String,
    
    #[validate(range(min = 1, max = 150, message = "年龄必须在 1-150 之间"))]
    pub age: Option<i32>,
    
    #[validate(url(message = "头像必须是有效的 URL"))]
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PaginationReq {
    #[validate(range(min = 1, max = 100))]
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    
    #[validate(range(min = 1))]
    #[serde(default = "default_page")]
    pub page: i64,
}

fn default_page_size() -> i64 { 20 }
fn default_page() -> i64 { 1 }
```

### 5.2 在 Handler 中验证

```rust
// src/api/handlers/user.rs
use axum::{extract::Json, http::StatusCode};
use validator::Validate;

pub async fn create_user(
    Json(req): Json<CreateUserReq>,
) -> Result<Json<UserResponse>, AppError> {
    // 执行验证
    req.validate()
        .map_err(|e| AppError::Validation(format_validation_errors(&e)))?;
    
    // 业务逻辑...
    let user = service::create_user(req).await?;
    Ok(Json(UserResponse::from(user)))
}

fn format_validation_errors(errors: &validator::ValidationErrors) -> String {
    errors
        .field_errors()
        .iter()
        .flat_map(|(field, errs)| {
            errs.iter().map(move |e| {
                format!("{}: {}", field, e.message.as_ref().map(|m| m.as_ref()).unwrap_or("无效"))
            })
        })
        .collect::<Vec<_>>()
        .join("; ")
}
```

### 5.3 HTML/XSS 清理

```rust
// src/utils/sanitize.rs
use ammonia::Builder;

/// 清理 HTML，只保留安全标签
pub fn sanitize_html(input: &str) -> String {
    Builder::default()
        .tags(hashset!["p", "br", "b", "i", "u", "strong", "em"])
        .clean(input)
        .to_string()
}

/// 完全移除 HTML 标签（纯文本）
pub fn strip_html(input: &str) -> String {
    Builder::empty()
        .clean(input)
        .to_string()
}

/// 清理用于 SQL LIKE 的输入
pub fn escape_like_pattern(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
```

### 5.4 输入验证规范要点

| 规则 | 说明 |
|------|------|
| 白名单优于黑名单 | 明确允许的字符/格式，拒绝其他 |
| 前后端都要验证 | 前端验证提升体验，后端验证保证安全 |
| 长度限制 | 所有字符串输入都必须有长度限制 |
| 类型验证 | 使用强类型，避免 `String` 万能类型 |
| 业务规则验证 | 在 Service 层验证业务逻辑约束 |

---

## 6. 敏感数据保护

### 6.1 使用 secrecy 包装敏感数据

```rust
// src/config.rs
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub database_url: SecretString,
    pub jwt_secret: SecretString,
    pub api_key: SecretString,
}

// 使用时显式暴露
fn connect_database(config: &Config) {
    let url = config.database_url.expose_secret();
    // ...
}
```

### 6.2 日志脱敏

```rust
// src/utils/logging.rs
use tracing::{info, warn};

// ❌ 危险：敏感信息进入日志
fn log_unsafe(user: &User, password: &str) {
    info!("用户登录: {:?}, 密码: {}", user, password);
}

// ✅ 安全：脱敏处理
fn log_safe(user: &User) {
    info!(
        user_id = %user.id,
        email = %mask_email(&user.email),
        "用户登录"
    );
}

/// 邮箱脱敏：a]b]c@example.com -> a**@example.com
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let masked = if local.len() <= 2 {
                "*".repeat(local.len())
            } else {
                format!("{}**", &local[..1])
            };
            format!("{}@{}", masked, domain)
        }
        None => "***".to_string(),
    }
}

/// 手机号脱敏：13812345678 -> 138****5678
pub fn mask_phone(phone: &str) -> String {
    if phone.len() >= 11 {
        format!("{}****{}", &phone[..3], &phone[phone.len()-4..])
    } else {
        "*".repeat(phone.len())
    }
}
```

### 6.3 响应数据过滤

```rust
// src/api/dto/user.rs
use serde::Serialize;

/// 用户响应 DTO（排除敏感字段）
#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub name: String,
    pub email: String,  // 考虑是否脱敏
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    // 不包含: password_hash, secret_key, etc.
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
        }
    }
}
```

### 6.4 敏感数据规范要点

| 规则 | 说明 |
|------|------|
| 使用 `SecretString` 包装 | 密码、密钥、Token 等 |
| 实现 `Debug` 时隐藏敏感字段 | 或使用 `#[derive(Debug)]` 排除 |
| 日志必须脱敏 | 邮箱、手机、身份证等 |
| 响应 DTO 独立定义 | 明确排除敏感字段 |
| 错误消息不含敏感信息 | "密码错误" 而非 "密码 xxx 错误" |

---

## 7. 速率限制与防暴力破解

### 7.1 基于 Tower 的速率限制

```rust
// src/api/middleware/rate_limit.rs
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;

pub type SharedRateLimiter = Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

/// 创建全局速率限制器
pub fn create_rate_limiter(requests_per_second: u32) -> SharedRateLimiter {
    Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(requests_per_second).unwrap()
    )))
}
```

### 7.2 登录防暴力破解

```rust
// src/auth/login_guard.rs
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub struct LoginGuard {
    attempts: RwLock<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    window: Duration,
    lockout_duration: Duration,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            max_attempts: 5,
            window: Duration::from_secs(300),      // 5 分钟窗口
            lockout_duration: Duration::from_secs(900), // 锁定 15 分钟
        }
    }
    
    /// 检查是否被锁定
    pub fn is_locked(&self, identifier: &str) -> bool {
        let attempts = self.attempts.read().unwrap();
        if let Some(times) = attempts.get(identifier) {
            let now = Instant::now();
            let recent: Vec<_> = times
                .iter()
                .filter(|t| now.duration_since(**t) < self.window)
                .collect();
            
            if recent.len() >= self.max_attempts {
                // 检查是否还在锁定期
                if let Some(last) = recent.last() {
                    return now.duration_since(**last) < self.lockout_duration;
                }
            }
        }
        false
    }
    
    /// 记录失败尝试
    pub fn record_failure(&self, identifier: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts
            .entry(identifier.to_string())
            .or_default()
            .push(Instant::now());
    }
    
    /// 登录成功后清除记录
    pub fn clear(&self, identifier: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(identifier);
    }
}
```

### 7.3 在登录流程中使用

```rust
// src/api/handlers/auth.rs
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> Result<Json<TokenResponse>, AppError> {
    let identifier = &req.email;
    
    // 检查是否被锁定
    if state.login_guard.is_locked(identifier) {
        return Err(AppError::TooManyRequests(
            "登录尝试次数过多，请 15 分钟后重试".into()
        ));
    }
    
    // 验证凭据
    let user = match db::get_user_by_email(&state.pool, identifier).await? {
        Some(u) => u,
        None => {
            state.login_guard.record_failure(identifier);
            // 使用相同的错误消息，防止用户枚举
            return Err(AppError::Unauthorized("邮箱或密码错误".into()));
        }
    };
    
    if !verify_password(&req.password, &user.password_hash) {
        state.login_guard.record_failure(identifier);
        return Err(AppError::Unauthorized("邮箱或密码错误".into()));
    }
    
    // 成功后清除失败记录
    state.login_guard.clear(identifier);
    
    let token = state.jwt_manager.create_access_token(&user.id.to_string(), &user.role, vec![])?;
    Ok(Json(TokenResponse { access_token: token }))
}
```

### 7.4 速率限制规范要点

| 规则 | 说明 |
|------|------|
| 全局 API 限流 | 如 1000 请求/分钟/IP |
| 登录接口单独限流 | 更严格，如 5 次/5分钟/账号 |
| 失败锁定机制 | 连续失败后锁定 15-30 分钟 |
| 统一错误响应 | 不区分"用户不存在"和"密码错误" |
| 记录可疑行为 | 频繁失败触发告警 |

---

## 8. 安全响应头配置

### 8.1 Axum 中间件实现

```rust
// src/api/middleware/security_headers.rs
use axum::{
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

pub async fn security_headers<B>(request: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    
    // 防止 MIME 类型嗅探
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff")
    );
    
    // 防止点击劫持
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY")
    );
    
    // 启用 XSS 过滤（现代浏览器已弃用，但对旧浏览器有效）
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block")
    );
    
    // 严格传输安全（仅 HTTPS）
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains")
    );
    
    // 内容安全策略
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
    );
    
    // 引用策略
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin")
    );
    
    response
}
```

### 8.2 安全响应头说明

| Header | 值 | 作用 |
|--------|-----|------|
| `X-Content-Type-Options` | `nosniff` | 防止 MIME 类型嗅探 |
| `X-Frame-Options` | `DENY` | 防止点击劫持 |
| `Strict-Transport-Security` | `max-age=31536000` | 强制 HTTPS |
| `Content-Security-Policy` | `default-src 'self'` | 限制资源加载来源 |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | 控制 Referrer 信息 |

---

## 9. 依赖配置参考

```toml
[package]
name = "secure-backend"
version = "0.1.0"
edition = "2024"

[dependencies]
# Web 框架
axum = "0.8"
tower = "0.5"
tokio = { version = "1", features = ["full"] }

# 数据库
sqlx = { version = "0.8", features = [
    "runtime-tokio",
    "tls-rustls-ring-webpki",
    "postgres"
] }

# 认证与加密
argon2 = "0.5"
jsonwebtoken = { version = "10", features = ["aws_lc_rs"] }
secrecy = "0.10"
rand = "0.9"

# 输入验证
validator = { version = "0.19", features = ["derive"] }
ammonia = "4"

# 速率限制
governor = "0.8"

# 序列化
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }

# 错误处理
thiserror = "2.0"
anyhow = "1.0"

# 日志
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# 工具
uuid = { version = "1", features = ["v4", "serde"] }
```

---

## 10. 团队约定清单

### ✅ 必须遵守

| 规则 | 说明 |
|------|------|
| 密码使用 Argon2 哈希 | 禁止 MD5/SHA1/SHA256 |
| 敏感数据用 `SecretString` | 密码、密钥、Token |
| SQL 100% 参数化 | 绝对禁止字符串拼接 |
| 所有输入必须验证 | 长度、格式、范围 |
| JWT 必须验证 `exp` | 防止过期 Token |
| 日志必须脱敏 | 邮箱、手机、密码等 |

### ❌ 禁止事项

| 规则 | 说明 |
|------|------|
| 禁止明文存储密码 | 只能存储哈希值 |
| 禁止硬编码密钥 | 必须从配置/环境变量读取 |
| 禁止 SQL 字符串拼接 | 即使是"可信"输入 |
| 禁止日志记录敏感信息 | 密码、Token、密钥 |
| 禁止在错误中暴露内部细节 | 用户侧返回通用错误 |
| 禁止信任客户端输入 | 所有输入都可能是恶意的 |

### 📝 Code Review 检查点

- [ ] 密码是否使用 `SecretString` 包装？
- [ ] 密码哈希是否使用 Argon2？
- [ ] SQL 查询是否 100% 参数化？
- [ ] 所有用户输入是否经过验证？
- [ ] 日志中是否存在敏感信息泄露？
- [ ] JWT 是否正确验证了过期时间？
- [ ] 错误响应是否泄露了内部细节？
- [ ] 是否实现了速率限制？

### 🚨 安全事件响应

| 事件 | 响应措施 |
|------|----------|
| 密钥泄露 | 立即轮换所有相关密钥，吊销现有 Token |
| SQL 注入发现 | 紧急修复，审计数据库访问日志 |
| 暴力破解检测 | 启用更严格的限流，考虑 IP 封禁 |
| 异常登录 | 通知用户，强制重置密码 |

---

## 11. 快速参考卡片

### 密码处理

```rust
use secrecy::{ExposeSecret, SecretString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

// 哈希
let salt = SaltString::generate(&mut OsRng);
let hash = Argon2::default()
    .hash_password(password.expose_secret().as_bytes(), &salt)?;

// 验证
PasswordHash::new(hash)
    .and_then(|h| Argon2::default().verify_password(pwd.as_bytes(), &h))
    .is_ok()
```

### JWT 操作

```rust
use jsonwebtoken::{encode, decode, Header, Validation, Algorithm};

// 生成
encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret))

// 验证
let mut validation = Validation::new(Algorithm::HS256);
validation.validate_exp = true;
decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
```

### SQL 安全查询

```rust
// 基本查询
sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)

// 动态查询
let mut builder = QueryBuilder::new("SELECT * FROM users WHERE 1=1");
if let Some(name) = &filter.name {
    builder.push(" AND name = ").push_bind(name);
}

// 可选参数
sqlx::query_as!(User, 
    "SELECT * FROM users WHERE ($1::text IS NULL OR name = $1)",
    name_opt
)
```

### 输入验证

```rust
use validator::Validate;

#[derive(Validate)]
pub struct Req {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    
    #[validate(email)]
    pub email: String,
    
    #[validate(range(min = 1, max = 100))]
    pub page_size: i64,
}

req.validate()?;
```

### 安全检查清单

```
□ 密码用 SecretString 包装
□ 密码用 Argon2 哈希（非明文）
□ JWT 密钥 ≥ 32 字符
□ JWT 设置并验证过期时间
□ SQL 100% 参数化查询
□ 分页有最大限制（如 100）
□ 所有输入已验证
□ 敏感数据不出现在日志
□ 错误响应不暴露内部细节
□ 已配置安全响应头
□ 登录接口有速率限制
```