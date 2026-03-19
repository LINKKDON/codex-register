# DuckMail 邮箱服务设计说明

**目标：** 为系统新增独立的 `duck_mail` 邮箱服务类型，支持在邮箱服务管理页配置 DuckMail，并在注册页选择该服务进行注册。

## 背景

当前项目已有三类邮箱服务：

- `tempmail`：公共临时邮箱
- `custom_domain`：MoeMail 风格 REST API
- `temp_mail`：自部署 Cloudflare Worker 临时邮箱

DuckMail 的接口模型与 `custom_domain` 不兼容。它采用 `/accounts`、`/token`、`/messages` 资源模型，并通过 Bearer Token 或 API Key 访问。因此需要新增独立服务类型，而不是复用现有 `custom_domain` 实现。

## 设计决策

### 1. 独立服务类型

新增 `duck_mail` 枚举值、服务类、前后端配置项与注册页可见性逻辑，避免与现有 MoeMail 接口混淆。

### 2. 配置模型

DuckMail 仅支持手动填写默认域名，不预拉取 `/domains`，配置项如下：

- `base_url`：DuckMail API 地址
- `default_domain`：默认域名，创建邮箱时直接拼接
- `password_length`：自动创建 DuckMail 账户时使用的随机密码长度
- `api_key`：可选，私有域名时通过 `Authorization: Bearer dk_xxx` 调用
- `timeout`
- `max_retries`
- `proxy_url`

### 3. 创建邮箱流程

DuckMail 服务在 `create_email()` 中：

1. 生成合法用户名（至少 3 个字符）
2. 用 `default_domain` 拼接邮箱地址
3. 生成随机密码
4. 调用 `POST /accounts`
5. 调用 `POST /token` 获取 Bearer Token
6. 返回 `email`、`service_id`、`account_id`、`token`、内部随机密码等信息

### 4. 取验证码流程

DuckMail 的列表接口不返回正文，需：

1. 轮询 `GET /messages`
2. 筛选 OpenAI 邮件
3. 对新消息调用 `GET /messages/{id}`
4. 从 `text/html` 中提取验证码

### 5. 删除与健康检查

- `delete_email()`：使用账户 Bearer Token 调 `DELETE /accounts/{id}`
- `check_health()`：优先调 `GET /domains`；如果配置了私有域名 API Key，也沿用相同入口

### 6. 前端接入

邮箱服务管理页新增 DuckMail 子类型：

- 列表中单独展示为 DuckMail
- 新建/编辑表单展示 DuckMail 专属字段

注册页：

- 从 `/registration/available-services` 中显示 DuckMail 服务
- 选择后与其他数据库邮箱服务一样传递 `email_service_type=duck_mail` 与 `email_service_id`

## 测试范围

至少覆盖：

- DuckMail `create_email()` 会调用账户创建与 token 获取
- DuckMail `get_verification_code()` 会按“列表 -> 详情”提取验证码
- 注册接口的可用服务列表包含 `duck_mail`
- 邮箱服务类型接口与敏感字段过滤支持 `duck_mail`
