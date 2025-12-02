# Rust 后端测试规范

---

## 目录

1. [核心原则](#1-核心原则)
2. [单元测试](#2-单元测试)
3. [Mock 与依赖隔离](#3-mock-与依赖隔离)
4. [集成测试](#4-集成测试)
5. [HTTP API 测试](#5-http-api-测试)
6. [数据库测试](#6-数据库测试)
7. [测试数据生成](#7-测试数据生成)
8. [测试工具与断言](#8-测试工具与断言)
9. [项目结构与组织](#9-项目结构与组织)
10. [依赖配置参考](#10-依赖配置参考)
11. [团队约定清单](#11-团队约定清单)
12. [快速参考卡片](#12-快速参考卡片)

---

## 1. 核心原则

| 原则 | 说明 | 实践 |
|------|------|------|
| **快速反馈** | 测试应快速执行，提供即时反馈 | 单元测试 < 100ms，集成测试 < 5s |
| **隔离性** | 测试之间互不影响，可独立运行 | 每个测试独立数据，测试后清理 |
| **可重复** | 任何时候运行结果一致 | 避免依赖时间、随机数、外部服务 |
| **可读性** | 测试即文档，清晰表达意图 | 命名规范：`test_<功能>_<场景>_<预期>` |

**一句话总结**：单元测试保证正确性，集成测试保证协作性，E2E 测试保证完整性。

### 测试金字塔

```
        /\
       /  \      E2E 测试（少量，慢，高成本）
      /----\
     /      \    集成测试（适量，中速）
    /--------\
   /          \  单元测试（大量，快速，低成本）
  --------------
```

| 层级 | 占比 | 执行时间 | 关注点 |
|------|------|----------|--------|
| 单元测试 | 70% | < 100ms | 函数逻辑、边界条件 |
| 集成测试 | 20% | < 5s | 模块协作、数据库交互 |
| E2E 测试 | 10% | < 30s | 完整业务流程 |

---

## 2. 单元测试

### 2.1 基础结构

```rust
// src/service/user.rs

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError::Empty("email"));
    }
    if !email.contains('@') {
        return Err(ValidationError::InvalidFormat("email"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ✅ 命名规范：test_<功能>_<场景>_<预期>
    #[test]
    fn test_validate_email_with_valid_input_returns_ok() {
        let result = validate_email("user@example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_email_with_empty_input_returns_error() {
        let result = validate_email("");
        assert!(matches!(result, Err(ValidationError::Empty(_))));
    }

    #[test]
    fn test_validate_email_without_at_symbol_returns_invalid_format() {
        let result = validate_email("invalid-email");
        assert!(matches!(result, Err(ValidationError::InvalidFormat(_))));
    }
}
```

### 2.2 异步测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_fetch_user_returns_user_when_exists() {
        let service = UserService::new_for_test();
        let user = service.fetch_user(1).await;
        assert!(user.is_ok());
    }

    // 带超时的异步测试
    #[tokio::test]
    async fn test_slow_operation_completes_within_timeout() {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            slow_async_operation()
        ).await;
        
        assert!(result.is_ok(), "操作超时");
    }

    // 测试异步错误
    #[tokio::test]
    async fn test_fetch_user_returns_not_found_when_missing() {
        let service = UserService::new_for_test();
        let result = service.fetch_user(99999).await;
        
        assert!(matches!(result, Err(ServiceError::NotFound { .. })));
    }
}
```

### 2.3 测试 panic 场景

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_get_item_panics_on_invalid_index() {
        let items = vec![1, 2, 3];
        let _ = items[10];  // 应该 panic
    }

    // 更精确的 panic 测试
    #[test]
    fn test_divide_by_zero_panics() {
        let result = std::panic::catch_unwind(|| {
            divide(10, 0)
        });
        
        assert!(result.is_err());
    }
}
```

### 2.4 参数化测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // 使用宏实现参数化测试
    macro_rules! test_cases {
        ($($name:ident: $input:expr => $expected:expr),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    assert_eq!(process($input), $expected);
                }
            )*
        };
    }

    test_cases! {
        test_process_empty: "" => "",
        test_process_single: "a" => "A",
        test_process_multiple: "hello" => "HELLO",
        test_process_with_spaces: "hello world" => "HELLO WORLD",
    }

    // 或使用循环（适合大量测试数据）
    #[test]
    fn test_validate_password_various_cases() {
        let cases = vec![
            ("Abc12345!", true, "valid password"),
            ("short", false, "too short"),
            ("nouppercase123!", false, "missing uppercase"),
            ("NOLOWERCASE123!", false, "missing lowercase"),
            ("NoNumbers!", false, "missing numbers"),
        ];

        for (password, expected, description) in cases {
            let result = validate_password(password).is_ok();
            assert_eq!(result, expected, "Case '{}' failed: {}", password, description);
        }
    }
}
```

### 2.5 单元测试规范要点

| 规则 | 说明 |
|------|------|
| 一个测试只测一件事 | 便于定位失败原因 |
| 命名清晰表达意图 | `test_<功能>_<场景>_<预期>` |
| 使用 AAA 模式 | Arrange（准备）→ Act（执行）→ Assert（断言） |
| 测试边界条件 | 空值、零值、最大值、负值等 |
| 避免测试私有函数 | 通过公共 API 测试 |
| 保持测试独立 | 不依赖其他测试的执行顺序 |

---

## 3. Mock 与依赖隔离

### 3.1 使用 mockall 定义 Mock

```rust
// src/repository/traits.rs
use mockall::automock;
use async_trait::async_trait;

#[automock]
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError>;
    async fn create(&self, user: &NewUser) -> Result<User, DbError>;
    async fn update(&self, user: &User) -> Result<User, DbError>;
    async fn delete(&self, id: i64) -> Result<(), DbError>;
}

#[automock]
pub trait EmailService: Send + Sync {
    fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError>;
    fn send_template(&self, to: &str, template: &str, data: &serde_json::Value) -> Result<(), EmailError>;
}

#[automock]
#[async_trait]
pub trait CacheService: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, CacheError>;
    async fn set(&self, key: &str, value: &str, ttl: u64) -> Result<(), CacheError>;
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
}
```

### 3.2 Mock 基本用法

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_get_user_returns_user_when_found() {
        // Arrange: 准备 Mock
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_find_by_id()
            .with(eq(1))
            .times(1)
            .returning(|_| Ok(Some(User {
                id: 1,
                name: "Alice".into(),
                email: "alice@example.com".into(),
            })));

        let service = UserService::new(Box::new(mock_repo));

        // Act: 执行
        let result = service.get_user(1).await;

        // Assert: 断言
        assert!(result.is_ok());
        let user = result.unwrap().unwrap();
        assert_eq!(user.name, "Alice");
    }

    #[tokio::test]
    async fn test_get_user_returns_none_when_not_found() {
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_find_by_id()
            .with(eq(999))
            .times(1)
            .returning(|_| Ok(None));

        let service = UserService::new(Box::new(mock_repo));
        let result = service.get_user(999).await.unwrap();

        assert!(result.is_none());
    }
}
```

### 3.3 Mock 高级用法

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::Sequence;

    // 验证调用顺序
    #[tokio::test]
    async fn test_registration_flow_calls_in_order() {
        let mut seq = Sequence::new();

        let mut mock_repo = MockUserRepository::new();
        let mut mock_email = MockEmailService::new();

        // 1. 先检查用户是否存在
        mock_repo
            .expect_find_by_email()
            .with(eq("new@example.com"))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(None));

        // 2. 创建用户
        mock_repo
            .expect_create()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(User { id: 1, name: "New".into(), email: "new@example.com".into() }));

        // 3. 发送欢迎邮件
        mock_email
            .expect_send_template()
            .with(eq("new@example.com"), eq("welcome"), always())
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _, _| Ok(()));

        let service = RegistrationService::new(
            Box::new(mock_repo),
            Box::new(mock_email),
        );

        let result = service.register("New", "new@example.com", "password").await;
        assert!(result.is_ok());
    }

    // 使用 withf 进行复杂参数匹配
    #[test]
    fn test_send_email_with_complex_validation() {
        let mut mock_email = MockEmailService::new();
        mock_email
            .expect_send()
            .withf(|to, subject, body| {
                to.ends_with("@example.com") &&
                subject.contains("Welcome") &&
                body.len() > 10
            })
            .times(1)
            .returning(|_, _, _| Ok(()));

        let service = NotificationService::new(Box::new(mock_email));
        service.send_welcome("user@example.com").unwrap();
    }

    // 返回不同结果
    #[tokio::test]
    async fn test_retry_on_failure() {
        let mut mock_repo = MockUserRepository::new();
        let call_count = std::sync::atomic::AtomicUsize::new(0);

        mock_repo
            .expect_find_by_id()
            .times(3)
            .returning(move |_| {
                let count = call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count < 2 {
                    Err(DbError::Connection("timeout".into()))
                } else {
                    Ok(Some(User { id: 1, name: "Test".into(), email: "t@t.com".into() }))
                }
            });

        let service = UserServiceWithRetry::new(Box::new(mock_repo));
        let result = service.get_user_with_retry(1, 3).await;

        assert!(result.is_ok());
    }
}
```

### 3.4 依赖注入模式

```rust
// 方式一：Trait Object（动态分发，更灵活）
pub struct UserService {
    repo: Box<dyn UserRepository>,
    email: Box<dyn EmailService>,
}

impl UserService {
    pub fn new(
        repo: Box<dyn UserRepository>,
        email: Box<dyn EmailService>,
    ) -> Self {
        Self { repo, email }
    }
}

// 方式二：泛型（静态分发，零成本抽象）
pub struct UserService<R, E>
where
    R: UserRepository,
    E: EmailService,
{
    repo: R,
    email: E,
}

impl<R, E> UserService<R, E>
where
    R: UserRepository,
    E: EmailService,
{
    pub fn new(repo: R, email: E) -> Self {
        Self { repo, email }
    }
}

// 方式三：使用 Arc（适合共享状态）
pub struct UserService {
    repo: Arc<dyn UserRepository>,
    cache: Arc<dyn CacheService>,
}
```

### 3.5 Mock 规范要点

| 规则 | 说明 |
|------|------|
| 只 Mock 外部依赖 | 数据库、HTTP 客户端、缓存等 |
| 使用 `#[automock]` | 自动生成 Mock 实现 |
| 明确设置 `times()` | 验证调用次数 |
| 使用 `with()` 验证参数 | 确保传入正确参数 |
| 避免过度 Mock | 不要 Mock 被测代码本身 |
| 优先使用 Trait Object | 测试更灵活 |

---

## 4. 集成测试

### 4.1 文件组织结构

```
project/
├── src/
│   ├── lib.rs
│   ├── main.rs
│   └── ...
├── tests/
│   ├── common/
│   │   ├── mod.rs          # 共享模块入口
│   │   ├── setup.rs        # 测试环境设置
│   │   ├── fixtures.rs     # 测试数据工厂
│   │   └── helpers.rs      # 辅助函数
│   ├── api/
│   │   ├── mod.rs
│   │   ├── user_tests.rs   # 用户 API 测试
│   │   └── order_tests.rs  # 订单 API 测试
│   ├── db/
│   │   ├── mod.rs
│   │   └── user_repo_tests.rs
│   └── integration_tests.rs  # 跨模块集成测试
```

### 4.2 共享测试工具

```rust
// tests/common/mod.rs
pub mod setup;
pub mod fixtures;
pub mod helpers;

pub use setup::*;
pub use fixtures::*;
pub use helpers::*;
```

```rust
// tests/common/setup.rs
use sqlx::PgPool;
use std::sync::Once;

static INIT: Once = Once::new();

/// 初始化测试环境（只执行一次）
pub fn init_test_env() {
    INIT.call_once(|| {
        dotenvy::from_filename(".env.test").ok();
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    });
}

/// 创建测试数据库连接池
pub async fn create_test_pool() -> PgPool {
    init_test_env();
    
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set");
    
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");
    
    // 运行迁移
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    
    pool
}

/// 测试上下文，自动清理
pub struct TestContext {
    pub pool: PgPool,
    pub app: axum::Router,
}

impl TestContext {
    pub async fn new() -> Self {
        let pool = create_test_pool().await;
        let app = create_test_app(pool.clone()).await;
        
        Self { pool, app }
    }
    
    pub async fn cleanup(&self) {
        sqlx::query("TRUNCATE users, orders, audit_logs RESTART IDENTITY CASCADE")
            .execute(&self.pool)
            .await
            .expect("Failed to cleanup");
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        // 同步清理或标记清理
    }
}
```

```rust
// tests/common/fixtures.rs
use fake::{Fake, Faker};
use fake::faker::internet::en::*;
use fake::faker::name::en::*;

/// 创建测试用户（数据库插入）
pub async fn create_test_user(pool: &PgPool) -> User {
    let name: String = Name().fake();
    let email: String = SafeEmail().fake();
    
    sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (name, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, name, email, created_at
        "#,
        name,
        email,
        "hashed_password"
    )
    .fetch_one(pool)
    .await
    .expect("Failed to create test user")
}

/// 创建指定数量的测试用户
pub async fn create_test_users(pool: &PgPool, count: usize) -> Vec<User> {
    let mut users = Vec::with_capacity(count);
    for _ in 0..count {
        users.push(create_test_user(pool).await);
    }
    users
}

/// 创建测试订单
pub async fn create_test_order(pool: &PgPool, user_id: i64) -> Order {
    sqlx::query_as!(
        Order,
        r#"
        INSERT INTO orders (user_id, total, status)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, total, status, created_at
        "#,
        user_id,
        Faker.fake::<f64>() * 100.0,
        "pending"
    )
    .fetch_one(pool)
    .await
    .expect("Failed to create test order")
}
```

### 4.3 集成测试示例

```rust
// tests/integration_tests.rs
mod common;

use common::{TestContext, create_test_user, create_test_order};

#[tokio::test]
async fn test_user_order_flow() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    // 1. 创建用户
    let user = create_test_user(&ctx.pool).await;
    assert!(user.id > 0);

    // 2. 创建订单
    let order = create_test_order(&ctx.pool, user.id).await;
    assert_eq!(order.user_id, user.id);
    assert_eq!(order.status, "pending");

    // 3. 验证关联
    let user_orders = sqlx::query_as!(
        Order,
        "SELECT * FROM orders WHERE user_id = $1",
        user.id
    )
    .fetch_all(&ctx.pool)
    .await
    .unwrap();

    assert_eq!(user_orders.len(), 1);
    assert_eq!(user_orders[0].id, order.id);

    ctx.cleanup().await;
}
```

### 4.4 集成测试规范要点

| 规则 | 说明 |
|------|------|
| 使用独立测试数据库 | 不与开发/生产数据库共享 |
| 每个测试前后清理数据 | 保证测试隔离 |
| 共享测试工具放 `tests/common/` | 避免重复代码 |
| 使用 `--test-threads=1` | 数据库测试串行执行 |
| 测试完整业务流程 | 多模块协作场景 |

---

## 5. HTTP API 测试

### 5.1 Axum 测试基础

```rust
// tests/api/mod.rs
use axum::{
    body::Body,
    http::{Request, StatusCode, Method, header},
};
use tower::ServiceExt;
use serde_json::{json, Value};

mod common;
use common::TestContext;

/// 发送请求的辅助函数
pub async fn send_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", t));
    }

    let body = body
        .map(|v| Body::from(v.to_string()))
        .unwrap_or(Body::empty());

    let request = builder.body(body).unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body)
}
```

### 5.2 API 测试示例

```rust
// tests/api/user_tests.rs
mod common;

use axum::http::{Method, StatusCode};
use serde_json::json;
use common::{TestContext, send_request, create_test_user};

#[tokio::test]
async fn test_health_check_returns_ok() {
    let ctx = TestContext::new().await;

    let (status, body) = send_request(
        &ctx.app,
        Method::GET,
        "/health",
        None,
        None,
    ).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_create_user_with_valid_data_returns_created() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let (status, body) = send_request(
        &ctx.app,
        Method::POST,
        "/api/users",
        Some(json!({
            "name": "Alice",
            "email": "alice@example.com",
            "password": "SecurePass123!"
        })),
        None,
    ).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["data"]["name"], "Alice");
    assert!(body["data"]["id"].as_i64().unwrap() > 0);

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_create_user_with_invalid_email_returns_bad_request() {
    let ctx = TestContext::new().await;

    let (status, body) = send_request(
        &ctx.app,
        Method::POST,
        "/api/users",
        Some(json!({
            "name": "Alice",
            "email": "invalid-email",
            "password": "SecurePass123!"
        })),
        None,
    ).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"]["message"].as_str().unwrap().contains("email"));
}

#[tokio::test]
async fn test_get_user_requires_authentication() {
    let ctx = TestContext::new().await;

    let (status, _) = send_request(
        &ctx.app,
        Method::GET,
        "/api/users/1",
        None,
        None,  // 无 Token
    ).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_user_with_valid_token_returns_user() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    // 创建用户并获取 Token
    let user = create_test_user(&ctx.pool).await;
    let token = create_test_token(user.id);

    let (status, body) = send_request(
        &ctx.app,
        Method::GET,
        &format!("/api/users/{}", user.id),
        None,
        Some(&token),
    ).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"], user.id);

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_get_nonexistent_user_returns_not_found() {
    let ctx = TestContext::new().await;
    let token = create_test_token(1);

    let (status, body) = send_request(
        &ctx.app,
        Method::GET,
        "/api/users/99999",
        None,
        Some(&token),
    ).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"]["message"].as_str().is_some());
}
```

### 5.3 外部 HTTP 服务 Mock（wiremock）

```rust
// tests/external_api_tests.rs
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header, body_json};
use serde_json::json;

#[tokio::test]
async fn test_external_payment_api_success() {
    // 启动 Mock 服务器
    let mock_server = MockServer::start().await;

    // 设置 Mock 响应
    Mock::given(method("POST"))
        .and(path("/api/v1/payments"))
        .and(header("Authorization", "Bearer test-api-key"))
        .and(body_json(json!({
            "amount": 100,
            "currency": "USD"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "id": "pay_123",
                    "status": "completed"
                }))
        )
        .expect(1)  // 期望调用 1 次
        .mount(&mock_server)
        .await;

    // 使用 Mock 服务器 URL
    let client = PaymentClient::new(&mock_server.uri(), "test-api-key");
    let result = client.create_payment(100, "USD").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, "completed");
}

#[tokio::test]
async fn test_external_api_timeout_handling() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(10))  // 模拟慢响应
        )
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri());
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.get_slow_endpoint()
    ).await;

    assert!(result.is_err(), "应该超时");
}

#[tokio::test]
async fn test_external_api_retry_on_failure() {
    let mock_server = MockServer::start().await;

    // 前两次失败，第三次成功
    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClientWithRetry::new(&mock_server.uri(), 3);
    let result = client.get_flaky().await;

    assert!(result.is_ok());
}
```

### 5.4 API 测试规范要点

| 规则 | 说明 |
|------|------|
| 测试所有 HTTP 状态码 | 200, 201, 400, 401, 403, 404, 500 等 |
| 测试认证/授权 | Token 缺失、过期、权限不足 |
| 测试输入验证 | 无效格式、边界值、必填字段 |
| 使用 wiremock 模拟外部服务 | 避免依赖真实第三方 API |
| 验证响应结构 | 字段存在性、类型正确性 |

---

## 6. 数据库测试

### 6.1 测试数据库设置

```rust
// tests/common/db.rs
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{clients::Cli, images::postgres::Postgres, Container};

/// 使用 Testcontainers 启动临时数据库
pub struct TestDb {
    _container: Container<'static, Postgres>,
    pub pool: PgPool,
}

impl TestDb {
    pub async fn new() -> Self {
        let docker = Cli::default();
        let container = docker.run(Postgres::default());
        let port = container.get_host_port_ipv4(5432);

        let database_url = format!(
            "postgres://postgres:postgres@localhost:{}/postgres",
            port
        );

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to connect");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate");

        Self {
            _container: container,
            pool,
        }
    }
}
```

### 6.2 Repository 测试

```rust
// tests/db/user_repo_tests.rs
mod common;

use common::{TestContext, create_test_user};

#[tokio::test]
async fn test_create_user_stores_correct_data() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let repo = UserRepository::new(ctx.pool.clone());
    let new_user = NewUser {
        name: "Test User".into(),
        email: "test@example.com".into(),
        password_hash: "hashed".into(),
    };

    let user = repo.create(&new_user).await.unwrap();

    assert!(user.id > 0);
    assert_eq!(user.name, "Test User");
    assert_eq!(user.email, "test@example.com");

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_find_by_email_returns_user_when_exists() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let created = create_test_user(&ctx.pool).await;
    let repo = UserRepository::new(ctx.pool.clone());

    let found = repo.find_by_email(&created.email).await.unwrap();

    assert!(found.is_some());
    assert_eq!(found.unwrap().id, created.id);

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_find_by_email_returns_none_when_not_exists() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let repo = UserRepository::new(ctx.pool.clone());
    let found = repo.find_by_email("nonexistent@example.com").await.unwrap();

    assert!(found.is_none());

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_update_user_modifies_fields() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let original = create_test_user(&ctx.pool).await;
    let repo = UserRepository::new(ctx.pool.clone());

    let mut updated = original.clone();
    updated.name = "Updated Name".into();

    let result = repo.update(&updated).await.unwrap();
    assert_eq!(result.name, "Updated Name");

    // 验证数据库中的数据
    let from_db = repo.find_by_id(original.id).await.unwrap().unwrap();
    assert_eq!(from_db.name, "Updated Name");

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_delete_user_removes_from_database() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let user = create_test_user(&ctx.pool).await;
    let repo = UserRepository::new(ctx.pool.clone());

    repo.delete(user.id).await.unwrap();

    let found = repo.find_by_id(user.id).await.unwrap();
    assert!(found.is_none());

    ctx.cleanup().await;
}

#[tokio::test]
async fn test_unique_constraint_prevents_duplicate_email() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let repo = UserRepository::new(ctx.pool.clone());
    let new_user = NewUser {
        name: "User 1".into(),
        email: "same@example.com".into(),
        password_hash: "hash".into(),
    };

    // 第一次创建成功
    repo.create(&new_user).await.unwrap();

    // 第二次应该失败
    let duplicate = NewUser {
        name: "User 2".into(),
        email: "same@example.com".into(),
        password_hash: "hash".into(),
    };
    let result = repo.create(&duplicate).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DbError::DuplicateEntry { .. }));

    ctx.cleanup().await;
}
```

### 6.3 事务测试

```rust
#[tokio::test]
async fn test_transaction_rollback_on_error() {
    let ctx = TestContext::new().await;
    ctx.cleanup().await;

    let result: Result<(), DbError> = async {
        let mut tx = ctx.pool.begin().await?;

        // 插入用户
        sqlx::query!("INSERT INTO users (name, email) VALUES ($1, $2)", "Test", "t@t.com")
            .execute(&mut *tx)
            .await?;

        // 模拟错误
        return Err(DbError::Validation("simulated error".into()));

        // tx.commit().await?;  // 不会执行
        // Ok(())
    }.await;

    assert!(result.is_err());

    // 验证数据未被插入
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);

    ctx.cleanup().await;
}
```

### 6.4 数据库测试规范要点

| 规则 | 说明 |
|------|------|
| 使用独立测试数据库 | 环境变量 `TEST_DATABASE_URL` |
| 每个测试清理数据 | `TRUNCATE ... RESTART IDENTITY CASCADE` |
| 串行执行 | `cargo test -- --test-threads=1` |
| 测试约束条件 | 唯一性、外键、NOT NULL 等 |
| 测试事务行为 | 提交、回滚、隔离级别 |
| 考虑使用 Testcontainers | 完全隔离的临时数据库 |

---

## 7. 测试数据生成

### 7.1 使用 fake 库

```rust
// tests/common/fixtures.rs
use fake::{Fake, Faker};
use fake::faker::internet::en::*;
use fake::faker::name::en::*;
use fake::faker::phone_number::en::*;
use fake::faker::address::en::*;
use fake::faker::company::en::*;

/// 自动生成测试数据的结构体
#[derive(Debug, Clone, Fake)]
pub struct FakeUser {
    #[fake(faker = "Name()")]
    pub name: String,
    
    #[fake(faker = "SafeEmail()")]
    pub email: String,
    
    #[fake(faker = "PhoneNumber()")]
    pub phone: String,
    
    #[fake(faker = "18..65")]
    pub age: u8,
}

#[derive(Debug, Clone, Fake)]
pub struct FakeAddress {
    #[fake(faker = "StreetName()")]
    pub street: String,
    
    #[fake(faker = "CityName()")]
    pub city: String,
    
    #[fake(faker = "StateName()")]
    pub state: String,
    
    #[fake(faker = "ZipCode()")]
    pub zip: String,
}

#[derive(Debug, Clone, Fake)]
pub struct FakeOrder {
    #[fake(faker = "1..1000")]
    pub user_id: i64,
    
    #[fake(faker = "10.0..10000.0")]
    pub total: f64,
    
    #[fake(faker = "1..100")]
    pub quantity: i32,
}
```

### 7.2 Builder 模式

```rust
// tests/common/builders.rs

/// 用户构建器，支持默认值和自定义
pub struct UserBuilder {
    name: Option<String>,
    email: Option<String>,
    role: String,
    is_active: bool,
}

impl UserBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            email: None,
            role: "user".into(),
            is_active: true,
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn email(mut self, email: &str) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn role(mut self, role: &str) -> Self {
        self.role = role.into();
        self
    }

    pub fn inactive(mut self) -> Self {
        self.is_active = false;
        self
    }

    pub fn build(self) -> NewUser {
        NewUser {
            name: self.name.unwrap_or_else(|| Name().fake()),
            email: self.email.unwrap_or_else(|| SafeEmail().fake()),
            role: self.role,
            is_active: self.is_active,
        }
    }

    pub async fn create(self, pool: &PgPool) -> User {
        let new_user = self.build();
        sqlx::query_as!(
            User,
            "INSERT INTO users (name, email, role, is_active) VALUES ($1, $2, $3, $4) RETURNING *",
            new_user.name,
            new_user.email,
            new_user.role,
            new_user.is_active
        )
        .fetch_one(pool)
        .await
        .expect("Failed to create user")
    }
}

// 使用示例
#[tokio::test]
async fn test_with_builder() {
    let ctx = TestContext::new().await;

    // 使用默认值
    let user1 = UserBuilder::new().create(&ctx.pool).await;

    // 自定义部分字段
    let admin = UserBuilder::new()
        .name("Admin")
        .role("admin")
        .create(&ctx.pool)
        .await;

    // 自定义所有字段
    let specific = UserBuilder::new()
        .name("Specific User")
        .email("specific@example.com")
        .role("moderator")
        .inactive()
        .create(&ctx.pool)
        .await;

    assert_eq!(admin.role, "admin");
    assert!(!specific.is_active);
}
```

### 7.3 测试数据规范要点

| 规则 | 说明 |
|------|------|
| 使用 fake 库生成随机数据 | 避免硬编码测试数据 |
| Builder 模式构建复杂对象 | 灵活指定部分字段 |
| 区分必要和随机数据 | 测试相关字段固定，其他随机 |
| 避免测试数据冲突 | 使用唯一标识符或随机值 |

---

## 8. 测试工具与断言

### 8.1 自定义断言宏

```rust
// tests/common/assertions.rs

/// 断言 Result 是 Ok 并返回值
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    };
}

/// 断言 Result 是特定类型的 Err
#[macro_export]
macro_rules! assert_err {
    ($expr:expr, $pattern:pat) => {
        match $expr {
            Err($pattern) => {}
            Err(e) => panic!("Expected specific error, got: {:?}", e),
            Ok(v) => panic!("Expected Err, got Ok: {:?}", v),
        }
    };
}

/// 断言 Option 是 Some 并返回值
#[macro_export]
macro_rules! assert_some {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => panic!("Expected Some, got None"),
        }
    };
}

/// 断言两个浮点数近似相等
#[macro_export]
macro_rules! assert_float_eq {
    ($a:expr, $b:expr, $epsilon:expr) => {
        assert!(
            ($a - $b).abs() < $epsilon,
            "Expected {} ≈ {} (epsilon: {})",
            $a, $b, $epsilon
        );
    };
}
```

### 8.2 使用示例

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_assertions() {
        // assert_ok!
        let result: Result<i32, &str> = Ok(42);
        let value = assert_ok!(result);
        assert_eq!(value, 42);

        // assert_err!
        let result: Result<(), ValidationError> = Err(ValidationError::Empty("field"));
        assert_err!(result, ValidationError::Empty(_));

        // assert_some!
        let option: Option<String> = Some("hello".into());
        let value = assert_some!(option);
        assert_eq!(value, "hello");

        // assert_float_eq!
        let a = 0.1 + 0.2;
        let b = 0.3;
        assert_float_eq!(a, b, 1e-10);
    }
}
```

### 8.3 测试辅助函数

```rust
// tests/common/helpers.rs

/// 等待条件满足（带超时）
pub async fn wait_for<F, Fut>(
    condition: F,
    timeout: std::time::Duration,
    interval: std::time::Duration,
) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(interval).await;
    }
    false
}

/// 重试执行（带指数退避）
pub async fn retry_with_backoff<F, Fut, T, E>(
    operation: F,
    max_retries: usize,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last_error = None;
    for i in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                let delay = std::time::Duration::from_millis(100 * 2u64.pow(i as u32));
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(last_error.unwrap())
}

// 使用示例
#[tokio::test]
async fn test_wait_for_condition() {
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();

    // 后台任务递增计数器
    tokio::spawn(async move {
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    // 等待计数器达到 3
    let result = wait_for(
        || async { counter.load(std::sync::atomic::Ordering::SeqCst) >= 3 },
        std::time::Duration::from_secs(2),
        std::time::Duration::from_millis(50),
    ).await;

    assert!(result, "计数器未能及时达到 3");
}
```

---

## 9. 项目结构与组织

### 9.1 完整项目结构

```
project/
├── src/
│   ├── lib.rs              # 库入口
│   ├── main.rs             # 应用入口
│   ├── api/
│   │   ├── mod.rs
│   │   ├── handlers/
│   │   └── middleware/
│   ├── service/
│   │   ├── mod.rs
│   │   └── user.rs         # 包含 #[cfg(test)] mod tests
│   ├── repository/
│   │   ├── mod.rs
│   │   ├── traits.rs       # #[automock] traits
│   │   └── user.rs
│   └── domain/
│       ├── mod.rs
│       └── user.rs         # 包含单元测试
│
├── tests/                   # 集成测试
│   ├── common/
│   │   ├── mod.rs
│   │   ├── setup.rs
│   │   ├── fixtures.rs
│   │   ├── builders.rs
│   │   ├── helpers.rs
│   │   └── assertions.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── user_tests.rs
│   │   └── order_tests.rs
│   ├── db/
│   │   ├── mod.rs
│   │   └── user_repo_tests.rs
│   └── integration_tests.rs
│
├── benches/                 # 性能测试
│   └── api_bench.rs
│
└── Cargo.toml
```

### 9.2 测试分类

| 类型 | 位置 | 运行方式 | 执行频率 | 关注点 |
|------|------|----------|----------|--------|
| 单元测试 | `src/**/*.rs` | `cargo test --lib` | 每次提交 | 函数逻辑 |
| 集成测试 | `tests/` | `cargo test --test '*'` | 每次 PR | 模块协作 |
| 文档测试 | `src/**/*.rs` | `cargo test --doc` | 每次提交 | 示例正确性 |
| 性能测试 | `benches/` | `cargo bench` | 每周/发布前 | 性能回归 |

### 9.3 CI 配置示例

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

env:
  CARGO_TERM_COLOR: always
  TEST_DATABASE_URL: postgres://postgres:postgres@localhost/test_db

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Cache
        uses: Swatinem/rust-cache@v2
      
      - name: Run migrations
        run: cargo sqlx migrate run
      
      - name: Run unit tests
        run: cargo test --lib
      
      - name: Run integration tests
        run: cargo test --test '*' -- --test-threads=1
      
      - name: Run doc tests
        run: cargo test --doc
```

---

## 10. 依赖配置参考

```toml
[package]
name = "my-backend"
version = "0.1.0"
edition = "2024"

[dependencies]
# ... 生产依赖

[dev-dependencies]
# 测试框架
tokio-test = "0.4"

# Mock
mockall = "0.13"

# 测试数据生成
fake = { version = "3", features = ["derive"] }
rand = "0.9"

# HTTP Mock
wiremock = "0.6"

# 容器化测试
testcontainers = "0.23"

# 数据库测试
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres"] }

# HTTP 测试
axum-test = "0.16"
tower = { version = "0.5", features = ["util"] }

# 断言增强
pretty_assertions = "1.4"
assert_matches = "1.5"

# 异步测试
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }

# 环境变量
dotenvy = "0.15"

# 日志
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-test = "0.2"
```

---

## 11. 团队约定清单

### ✅ 必须遵守

| 规则 | 说明 |
|------|------|
| 核心业务逻辑 100% 单元测试覆盖 | 重要函数必须有测试 |
| 使用 `#[automock]` 隔离依赖 | 通过 Trait 注入依赖 |
| 集成测试使用独立数据库 | 不与开发环境共享 |
| 每个测试独立清理数据 | 测试前后 `cleanup()` |
| 测试命名清晰表达意图 | `test_<功能>_<场景>_<预期>` |
| PR 必须通过所有测试 | CI 强制执行 |

### ❌ 禁止事项

| 规则 | 说明 |
|------|------|
| 禁止测试依赖执行顺序 | 每个测试必须独立 |
| 禁止 Mock 被测代码本身 | 只 Mock 外部依赖 |
| 禁止使用真实外部服务 | 必须使用 wiremock 等模拟 |
| 禁止硬编码敏感数据 | 使用假数据或环境变量 |
| 禁止 `#[ignore]` 长期存在 | 临时跳过需附带 issue 链接 |
| 禁止测试中使用 `sleep` 等待 | 使用 `wait_for` 或条件等待 |

### 📝 Code Review 检查点

- [ ] 新功能是否有对应的单元测试？
- [ ] 测试是否覆盖正常路径和异常路径？
- [ ] 是否使用了有意义的测试数据？
- [ ] Mock 是否正确设置了预期？
- [ ] 集成测试是否正确清理了数据？
- [ ] 测试是否可以独立运行？
- [ ] 测试命名是否清晰？

### 📊 覆盖率要求

| 模块 | 最低覆盖率 | 说明 |
|------|------------|------|
| `domain/` | 90% | 核心业务逻辑 |
| `service/` | 80% | 业务服务层 |
| `repository/` | 70% | 数据访问层（集成测试补充） |
| `api/handlers/` | 60% | API 层（集成测试补充） |

---

## 12. 快速参考卡片

### 测试属性

```rust
#[test]                           // 同步测试
#[tokio::test]                    // 异步测试
#[should_panic(expected = "msg")] // 预期 panic
#[ignore]                         // 跳过测试
#[cfg(test)]                      // 条件编译
```

### 常用断言

```rust
assert!(condition);               // 条件为真
assert_eq!(left, right);          // 相等
assert_ne!(left, right);          // 不相等
assert!(matches!(expr, pattern)); // 模式匹配

// pretty_assertions
use pretty_assertions::{assert_eq, assert_ne};
```

### mockall 用法

```rust
use mockall::{automock, predicate::*};

#[automock]
trait MyTrait {
    fn method(&self, arg: i32) -> String;
}

// 测试中
let mut mock = MockMyTrait::new();
mock.expect_method()
    .with(eq(42))           // 参数匹配
    .times(1)               // 调用次数
    .returning(|_| "ok".into());  // 返回值
```

### 异步测试

```rust
#[tokio::test]
async fn test_async() {
    let result = async_fn().await;
    assert!(result.is_ok());
}

// 带超时
tokio::time::timeout(Duration::from_secs(5), async_fn()).await
```

### fake 数据生成

```rust
use fake::{Fake, Faker};
use fake::faker::internet::en::*;

let email: String = SafeEmail().fake();
let name: String = Name().fake();
let age: u8 = (18..65).fake();
```

### 运行测试命令

```bash
cargo test                        # 所有测试
cargo test test_name              # 特定测试
cargo test --lib                  # 仅单元测试
cargo test --test '*'             # 仅集成测试
cargo test -- --nocapture         # 显示输出
cargo test -- --test-threads=1    # 串行执行
cargo test -- --ignored           # 运行忽略的测试
```

### 测试目录结构

```
tests/
├── common/
│   ├── mod.rs      # pub mod setup, fixtures, helpers;
│   ├── setup.rs    # TestContext, create_test_pool
│   ├── fixtures.rs # create_test_user, builders
│   └── helpers.rs  # wait_for, retry
├── api/
│   └── user_tests.rs
└── db/
    └── repo_tests.rs
```

### AAA 模式模板

```rust
#[tokio::test]
async fn test_example() {
    // Arrange: 准备测试数据和依赖
    let ctx = TestContext::new().await;
    ctx.cleanup().await;
    let user = create_test_user(&ctx.pool).await;

    // Act: 执行被测操作
    let result = service.do_something(user.id).await;

    // Assert: 验证结果
    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, "completed");

    // Cleanup
    ctx.cleanup().await;
}
```