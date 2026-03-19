# DuckMail 邮箱服务实现计划

> **给 Codex：** 必须按 TDD 执行本计划，先写失败测试，再写最小实现。

**目标：** 新增独立 `duck_mail` 邮箱服务类型，支持 DuckMail 配置、测试、注册可见性与实际验证码拉取。

**架构：** 在现有 `BaseEmailService` 体系中新增 `DuckMailService`，并把它接入服务工厂、邮箱服务管理 API、注册可用服务 API 与前端页面。DuckMail 不复用 `custom_domain` 逻辑，单独维护请求头、创建邮箱、登录取 token、拉取消息与删除账户逻辑。

**技术栈：** Python、FastAPI、SQLAlchemy、原生 JavaScript、pytest

---

### 任务 1：补 DuckMail 服务层测试

**文件：**
- 新建：`tests/test_duck_mail_service.py`
- 参考：`src/services/temp_mail.py`
- 参考：`src/services/moe_mail.py`

**步骤 1：写失败测试**

- 测试 `create_email()`：
  - 会先调用 `POST /accounts`
  - 再调用 `POST /token`
  - 返回值包含 `email`、`service_id`、`account_id`、`token`
- 测试 `get_verification_code()`：
  - 先调 `GET /messages`
  - 再调 `GET /messages/{id}`
  - 能从正文提取 6 位验证码

**步骤 2：运行失败测试**

运行：`pytest tests/test_duck_mail_service.py -q`

预期：因为 `DuckMailService` 尚不存在而失败。

**步骤 3：写最小实现**

- 新增 `src/services/duck_mail.py`
- 只实现本轮测试所需的最小方法：
  - 初始化配置
  - 请求封装
  - 创建邮箱
  - 获取 token
  - 拉取消息与验证码
  - 删除账户
  - 健康检查

**步骤 4：运行测试确认通过**

运行：`pytest tests/test_duck_mail_service.py -q`

### 任务 2：补服务枚举与工厂接入测试

**文件：**
- 新建：`tests/test_email_service_duckmail_routes.py`
- 修改：`src/config/constants.py`
- 修改：`src/services/__init__.py`

**步骤 1：写失败测试**

- 断言 `EmailServiceType("duck_mail")` 可用
- 断言 `EmailServiceFactory.get_service_class(EmailServiceType.DUCK_MAIL)` 已注册

**步骤 2：运行失败测试**

运行：`pytest tests/test_email_service_duckmail_routes.py::test_duck_mail_service_registered -q`

**步骤 3：写最小实现**

- 在枚举中加入 `DUCK_MAIL`
- 在服务工厂注册 `DuckMailService`

**步骤 4：运行测试确认通过**

运行：`pytest tests/test_email_service_duckmail_routes.py::test_duck_mail_service_registered -q`

### 任务 3：补邮箱服务 API 与注册可见性测试

**文件：**
- 修改：`src/web/routes/email.py`
- 修改：`src/web/routes/registration.py`
- 参考：`src/database/models.py`

**步骤 1：写失败测试**

- 测试邮箱服务类型接口包含 `duck_mail`
- 测试敏感配置过滤支持 `api_key`
- 测试 `/registration/available-services` 会返回 `duck_mail`

**步骤 2：运行失败测试**

运行：`pytest tests/test_email_service_duckmail_routes.py -q`

**步骤 3：写最小实现**

- `email.py`
  - 统计增加 `duck_mail_count`
  - `get_service_types()` 增加 DuckMail 配置项
- `registration.py`
  - `available-services` 增加 `duck_mail`
  - `_normalize_email_service_config()` 支持 DuckMail 字段
  - `_run_sync_registration_task()` 支持 DuckMail 默认选择逻辑

**步骤 4：运行测试确认通过**

运行：`pytest tests/test_email_service_duckmail_routes.py -q`

### 任务 4：补前端 DuckMail 配置与注册入口

**文件：**
- 修改：`templates/email_services.html`
- 修改：`static/js/email_services.js`
- 修改：`static/js/app.js`
- 可选修改：`templates/index.html`

**步骤 1：先补最小前端逻辑**

- 邮箱服务页新增 DuckMail 类型展示与新建/编辑字段
- 注册页邮箱服务下拉新增 DuckMail 分组
- 选择 DuckMail 时传 `duck_mail:<id>`

**步骤 2：人工自检**

- 检查新增字段是否与后端字段名一致：
  - `base_url`
  - `api_key`
  - `default_domain`
  - `password_length`

### 任务 5：完整验证

**文件：**
- 修改：`README.md`

**步骤 1：补文档**

- 在功能列表与邮箱服务说明中加入 DuckMail

**步骤 2：运行完整验证**

运行：`pytest tests/test_duck_mail_service.py tests/test_email_service_duckmail_routes.py -q`

如环境允许，再运行：

`python -m compileall src`

**步骤 3：检查结果**

- 确认 pytest 退出码为 0
- 确认编译检查无语法错误
