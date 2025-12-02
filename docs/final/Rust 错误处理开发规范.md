# Rust 错误处理开发规范

---

## 目录

1. [核心原则](#1-核心原则)
2. [thiserror：模块级错误定义](#2-thiserror模块级错误定义)
3. [anyhow：应用层错误处理](#3-anyhow应用层错误处理)
4. [边界转换模式](#4-边界转换模式)
5. [HTTP 错误响应集成](#5-http-错误响应集成)
6. [项目结构建议](#6-项目结构建议)
7. [团队约定清单](#7-团队约定清单)
8. [快速参考卡片](#8-快速参考卡片)

---

## 1. 核心原则

| 场景 | 使用 | 理由 |
|------|------|------|
| **库 / 模块边界** | `thiserror` | 提供结构化、可 `match` 的错误类型 |
| **应用层 / 业务逻辑** | `anyhow` | 快速开发，自动附加上下文链 |

**一句话总结**：对外暴露用 `thiserror`，内部串联用 `anyhow`。

---

## 2. thiserror：模块级错误定义

### 2.1 基本用法

用于对外暴露的模块，让调用者能精确处理不同错误场景。

```rust
// src/db/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("数据库连接失败: {0}")]
    Connection(#[from] sqlx::Error),
    
    #[error("记录不存在: {table}.{id}")]
    NotFound { table: &'static str, id: i64 },
    
    #[error("数据校验失败: {0}")]
    Validation(String),
    
    #[error("唯一约束冲突: {field}")]
    DuplicateEntry { field: String },
}
```

### 2.2 在模块中使用

```rust
// src/db/user.rs
use super::error::DbError;

pub async fn get_user(id: i64) -> Result<User, DbError> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
        .fetch_optional(&pool)
        .await?;  // sqlx::Error 通过 #[from] 自动转换
    
    user.ok_or(DbError::NotFound { table: "users", id })
}

pub async fn create_user(req: &CreateUserReq) -> Result<User, DbError> {
    if req.email.is_empty() {
        return Err(DbError::Validation("邮箱不能为空".into()));
    }
    // ...
}
```

### 2.3 thiserror 规范要点

| 规则 | 说明 |
|------|------|
| 每个核心模块一个错误枚举 | `db::DbError`, `auth::AuthError`, `api::ApiError` |
| 变体命名用 `PascalCase` | `NotFound`, `Validation`, `Unauthorized` |
| `#[from]` 只用于 1:1 映射 | 底层错误到模块错误的直接转换 |
| 错误消息要有上下文 | 包含关键参数，便于调试 |

---

## 3. anyhow：应用层错误处理

### 3.1 基本用法

用于 main 函数、HTTP handlers、业务逻辑串联等场景。

```rust
// src/handlers/user.rs
use anyhow::{Context, Result, bail, ensure};

pub async fn create_user(req: CreateUserReq) -> Result<User> {
    // ensure! 宏：条件检查，失败时返回错误
    ensure!(!req.email.is_empty(), "邮箱不能为空");
    ensure!(req.age >= 18, "用户年龄必须 >= 18，当前: {}", req.age);
    
    // context()：附加静态上下文信息
    let user = db::create_user(&req)
        .await
        .context("创建用户记录失败")?;
    
    // with_context()：延迟计算（避免不必要的 format!）
    email::send_welcome(&user)
        .await
        .with_context(|| format!("发送欢迎邮件失败: {}", user.email))?;
    
    audit::log_action("user_created", &user)
        .context("审计日志写入失败")?;
    
    Ok(user)
}
```

### 3.2 bail! 宏：提前返回

```rust
pub async fn delete_user(id: i64, operator: &User) -> Result<()> {
    if !operator.is_admin {
        bail!("权限不足：需要管理员权限");
    }
    
    if id == operator.id {
        bail!("不能删除自己的账号");
    }
    
    db::delete_user(id)
        .await
        .with_context(|| format!("删除用户失败: id={}", id))?;
    
    Ok(())
}
```

### 3.3 anyhow 规范要点

| 规则 | 说明 |
|------|------|
| 所有 `?` 都应考虑加 `.context()` | 除非原错误信息已足够清晰 |
| 优先用 `context()` | 只有需要动态信息时才用 `with_context()` |
| `bail!` 用于业务逻辑错误 | 权限检查、参数校验等 |
| `ensure!` 用于前置条件检查 | 更简洁的条件断言 |

---

## 4. 边界转换模式

### 4.1 简单转换

在 handler 中将模块错误转为 anyhow：

```rust
pub async fn get_user_handler(id: i64) -> Result<Json<User>> {
    let user = db::get_user(id)
        .await
        .context("查询用户失败")?;  // DbError → anyhow::Error
    
    Ok(Json(user))
}
```

### 4.2 精确处理

需要区分不同错误类型时：

```rust
pub async fn get_user_handler(id: i64) -> Result<Json<User>> {
    match db::get_user(id).await {
        Ok(user) => Ok(Json(user)),
        Err(DbError::NotFound { .. }) => {
            bail!("用户 {} 不存在", id)
        }
        Err(DbError::Connection(e)) => {
            tracing::error!("数据库连接异常: {:?}", e);
            bail!("服务暂时不可用，请稍后重试")
        }
        Err(e) => {
            Err(e).context("查询用户时发生未知错误")?
        }
    }
}
```

### 4.3 错误链检查

使用 `downcast_ref` 检查错误链中的特定类型：

```rust
fn handle_error(err: &anyhow::Error) -> StatusCode {
    // 检查错误链中是否包含特定类型
    if let Some(db_err) = err.downcast_ref::<DbError>() {
        match db_err {
            DbError::NotFound { .. } => StatusCode::NOT_FOUND,
            DbError::Validation(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    } else if let Some(_) = err.downcast_ref::<AuthError>() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}
```

---

## 5. HTTP 错误响应集成

### 5.1 Axum 集成示例

```rust
// src/api/error.rs
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;

/// 统一的 API 错误包装器
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 始终记录完整错误链
        tracing::error!("{:?}", self.0);
        
        let (status, message) = extract_error_info(&self.0);
        
        let body = Json(json!({
            "success": false,
            "error": {
                "message": message,
                "code": status.as_u16()
            }
        }));
        
        (status, body).into_response()
    }
}

fn extract_error_info(err: &anyhow::Error) -> (StatusCode, String) {
    // 尝试从错误链中提取已知类型
    if let Some(db_err) = err.downcast_ref::<DbError>() {
        match db_err {
            DbError::NotFound { table, id } => {
                (StatusCode::NOT_FOUND, format!("{}({}) 不存在", table, id))
            }
            DbError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, msg.clone())
            }
            DbError::DuplicateEntry { field } => {
                (StatusCode::CONFLICT, format!("{} 已存在", field))
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "数据库错误".into()),
        }
    } else if let Some(auth_err) = err.downcast_ref::<AuthError>() {
        match auth_err {
            AuthError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, "无效的认证令牌".into())
            }
            AuthError::Expired => {
                (StatusCode::UNAUTHORIZED, "认证已过期".into())
            }
            AuthError::Forbidden => {
                (StatusCode::FORBIDDEN, "权限不足".into())
            }
        }
    } else {
        // 生产环境不暴露内部错误详情
        (StatusCode::INTERNAL_SERVER_ERROR, "服务器内部错误".into())
    }
}

// 实现 From trait，让 ? 操作符自动转换
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
```

### 5.2 Handler 中使用

```rust
// src/api/handlers/user.rs
use crate::api::error::AppError;

pub async fn create_user(
    Json(req): Json<CreateUserReq>,
) -> Result<Json<UserResponse>, AppError> {
    let user = service::create_user(req)
        .await
        .context("创建用户失败")?;
    
    Ok(Json(UserResponse::from(user)))
}
```

---

## 6. 项目结构建议

```
src/
├── main.rs
├── lib.rs
│
├── error.rs              # [可选] 全局 AppError 定义
│
├── db/
│   ├── mod.rs
│   ├── error.rs          # DbError 定义
│   ├── user.rs
│   └── order.rs
│
├── auth/
│   ├── mod.rs
│   ├── error.rs          # AuthError 定义
│   ├── jwt.rs
│   └── middleware.rs
│
├── service/              # 业务逻辑层，使用 anyhow
│   ├── mod.rs
│   ├── user.rs
│   └── order.rs
│
└── api/
    ├── mod.rs
    ├── error.rs          # AppError (HTTP 响应映射)
    ├── routes.rs
    └── handlers/
        ├── mod.rs
        ├── user.rs
        └── order.rs
```

### 错误类型分布

| 层级 | 错误类型 | 说明 |
|------|----------|------|
| `db/` | `DbError` (thiserror) | 数据库操作错误 |
| `auth/` | `AuthError` (thiserror) | 认证授权错误 |
| `service/` | `anyhow::Error` | 串联各模块，附加业务上下文 |
| `api/` | `AppError` | 包装 anyhow，转换为 HTTP 响应 |

---

## 7. 团队约定清单

### ✅ 必须遵守

| 规则 | 说明 |
|------|------|
| 库/模块代码用 `thiserror` | 对外 API 必须有明确错误类型 |
| 应用代码用 `anyhow` | handler、service、main 等 |
| 所有 `?` 加 `.context()` | 除非错误信息已足够清晰 |
| 日志打印用 `{:?}` | 显示完整错误链 |
| 错误消息包含关键参数 | `"用户 {id} 不存在"` 而非 `"用户不存在"` |

### ❌ 禁止事项

| 规则 | 说明 |
|------|------|
| 禁止 `.unwrap()` | 除非 100% 确定不会 panic（需注释说明） |
| 禁止 `.expect()` 用于可恢复错误 | 只用于程序逻辑错误 |
| 禁止忽略 `Result` | `let _ = xxx()` 需 Code Review 确认 |
| 禁止在错误消息中暴露敏感信息 | 密码、token、内部路径等 |

### 📝 Code Review 检查点

- [ ] 模块边界是否使用了 `thiserror` 定义错误类型？
- [ ] `?` 操作符是否附加了有意义的 context？
- [ ] 错误消息是否包含足够的调试信息？
- [ ] 是否有未处理的 `Result`？
- [ ] HTTP 响应是否正确映射了错误码？

---

## 8. 快速参考卡片

### thiserror 派生宏

```rust
#[derive(Error, Debug)]
pub enum MyError {
    #[error("消息 {field}")]           // 格式化字段
    Variant { field: String },
    
    #[error("包装: {0}")]              // 包装其他错误
    Wrapped(#[from] std::io::Error),
    
    #[error(transparent)]              // 透传底层错误消息
    Other(#[from] anyhow::Error),
}
```

### anyhow 常用 API

```rust
use anyhow::{anyhow, bail, ensure, Context, Result};

// 创建错误
let err = anyhow!("发生错误: {}", detail);

// 提前返回
bail!("条件不满足");

// 条件检查
ensure!(x > 0, "x 必须大于 0，当前值: {}", x);

// 附加上下文
do_something().context("执行某操作时失败")?;
do_something().with_context(|| format!("处理 {} 失败", id))?;

// 错误链操作
err.chain()              // 遍历错误链
err.root_cause()         // 获取根本原因
err.downcast_ref::<T>()  // 尝试转换为具体类型
```

### 日志记录最佳实践

```rust
// ✅ 正确：使用 {:?} 打印完整错误链
tracing::error!("操作失败: {:?}", err);

// ✅ 正确：结构化日志
tracing::error!(
    error = ?err,
    user_id = %user_id,
    "创建订单失败"
);

// ❌ 错误：只打印错误消息，丢失错误链
tracing::error!("操作失败: {}", err);
```
