"""
注册流程引擎
从 MREGISTER 项目移植的正确注册流程
"""

import re
import json
import time
import logging
import secrets
import string
import random
import uuid
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass
from datetime import datetime

from curl_cffi import requests as cffi_requests

from .openai.oauth import OAuthManager, OAuthStart
from .openai.sentinel_token import build_sentinel_token, generate_datadog_trace
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)


_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]


def _random_chrome_version():
    """随机选择一个 Chrome 版本"""
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""
    is_existing_account: bool = False
    response_data: Dict[str, Any] = None
    error_message: str = ""


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid

        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.device_id = str(uuid.uuid4())

        self.session: Optional[cffi_requests.Session] = None
        self._init_session()

        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url
        )

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session_token: Optional[str] = None
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None
        self._is_existing_account: bool = False

    def _init_session(self):
        """初始化会话"""
        self.session = cffi_requests.Session(impersonate=self.impersonate)
        
        if self.proxy_url:
            self.session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8",
                "en,en-US;q=0.9", "en-US,en;q=0.8",
            ]),
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        self.logs.append(log_message)

        if self.callback_logger:
            self.callback_logger(log_message)

        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        try:
            response = self.session.get(
                "https://cloudflare.com/cdn-cgi/trace",
                timeout=10
            )
            trace_text = response.text

            import re
            loc_match = re.search(r"loc=([A-Z]+)", trace_text)
            loc = loc_match.group(1) if loc_match else None

            if loc in ["CN", "HK", "MO", "TW"]:
                return False, loc
            return True, loc

        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            self.email = self.email_info["email"]
            self._log(f"成功创建邮箱: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _visit_homepage(self) -> bool:
        """访问 ChatGPT 首页"""
        self._log("访问 ChatGPT 首页...")
        try:
            r = self.session.get(
                f"{self.BASE}/",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=True,
                timeout=30
            )
            return r.status_code == 200
        except Exception as e:
            self._log(f"访问首页失败: {e}", "error")
            return False

    def _get_csrf_token(self) -> Optional[str]:
        """获取 CSRF token"""
        self._log("获取 CSRF token...")
        try:
            r = self.session.get(
                f"{self.BASE}/api/auth/csrf",
                headers={
                    "Accept": "application/json",
                    "Referer": f"{self.BASE}/"
                },
                timeout=30
            )

            if r.status_code == 200:
                data = r.json()
                token = data.get("csrfToken", "")
                if token:
                    self._log(f"CSRF token: {token[:20]}...")
                    return token
        except Exception as e:
            self._log(f"获取 CSRF token 失败: {e}", "error")

        return None

    def _signin_email(self, email: str, csrf_token: str) -> Optional[str]:
        """提交邮箱，获取 authorize URL"""
        self._log(f"提交邮箱: {email}")
        url = f"{self.BASE}/api/auth/signin/openai"

        params = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }

        form_data = {
            "callbackUrl": f"{self.BASE}/",
            "csrfToken": csrf_token,
            "json": "true",
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Referer": f"{self.BASE}/",
            "Origin": self.BASE,
        }

        try:
            r = self.session.post(
                url,
                params=params,
                data=form_data,
                headers=headers,
                timeout=30
            )

            if r.status_code == 200:
                data = r.json()
                authorize_url = data.get("url", "")
                if authorize_url:
                    self._log(f"获取到 authorize URL")
                    return authorize_url
        except Exception as e:
            self._log(f"提交邮箱失败: {e}", "error")

        return None

    def _authorize(self, auth_url: str, max_retries: int = 3) -> str:
        """访问 authorize URL，跟随重定向"""
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    self._log(f"访问 authorize URL... (尝试 {attempt + 1}/{max_retries})")
                    time.sleep(1)
                else:
                    self._log("访问 authorize URL...")

                r = self.session.get(
                    auth_url,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": f"{self.BASE}/",
                        "Upgrade-Insecure-Requests": "1",
                    },
                    allow_redirects=True,
                    timeout=30
                )

                final_url = str(r.url)
                self._log(f"重定向到: {final_url}")
                return final_url

            except Exception as e:
                error_msg = str(e)
                is_tls_error = "TLS" in error_msg or "SSL" in error_msg or "curl: (35)" in error_msg

                if is_tls_error and attempt < max_retries - 1:
                    self._log(f"Authorize TLS 错误 (尝试 {attempt + 1}/{max_retries}): {error_msg[:100]}")
                    continue
                else:
                    self._log(f"Authorize 失败: {e}", "error")
                    return ""

        return ""

    def _register_user(self, email: str, password: str) -> Tuple[bool, str]:
        """注册用户（邮箱 + 密码）"""
        self._log(f"注册用户: {email}")
        url = f"{self.AUTH}/api/accounts/user/register"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/create-account/password",
            "Origin": self.AUTH,
        }
        headers.update(generate_datadog_trace())

        payload = {
            "username": email,
            "password": password,
        }

        try:
            r = self.session.post(url, json=payload, headers=headers, timeout=30)

            if r.status_code == 200:
                self._log("注册成功")
                return True, "注册成功"
            else:
                try:
                    error_data = r.json()
                    error_msg = error_data.get("error", {}).get("message", r.text[:200])
                except:
                    error_msg = r.text[:200]
                self._log(f"注册失败: {r.status_code} - {error_msg}", "warning")
                return False, f"HTTP {r.status_code}: {error_msg}"

        except Exception as e:
            self._log(f"注册异常: {e}", "error")
            return False, str(e)

    def _send_email_otp(self) -> bool:
        """触发发送邮箱验证码"""
        self._log("触发发送验证码...")
        url = f"{self.AUTH}/api/accounts/email-otp/send"

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.AUTH}/create-account/password",
            "Upgrade-Insecure-Requests": "1",
        }

        try:
            r = self.session.get(url, headers=headers, allow_redirects=True, timeout=30)
            return r.status_code == 200
        except Exception as e:
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _verify_email_otp(self, otp_code: str) -> Tuple[bool, str]:
        """验证邮箱 OTP 码"""
        self._log(f"验证 OTP 码: {otp_code}")
        url = f"{self.AUTH}/api/accounts/email-otp/validate"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/email-verification",
            "Origin": self.AUTH,
        }
        headers.update(generate_datadog_trace())

        payload = {"code": otp_code}

        try:
            r = self.session.post(url, json=payload, headers=headers, timeout=30)

            if r.status_code == 200:
                self._log("验证成功")
                return True, "验证成功"
            else:
                error_msg = r.text[:200]
                self._log(f"验证失败: {r.status_code} - {error_msg}", "warning")
                return False, f"HTTP {r.status_code}"

        except Exception as e:
            self._log(f"验证异常: {e}", "error")
            return False, str(e)

    def _create_account(self, first_name: str, last_name: str, birthdate: str) -> Tuple[bool, str]:
        """完成账号创建（提交姓名和生日）"""
        name = f"{first_name} {last_name}"
        self._log(f"完成账号创建: {name}")
        url = f"{self.AUTH}/api/accounts/create_account"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/about-you",
            "Origin": self.AUTH,
        }
        headers.update(generate_datadog_trace())

        payload = {
            "name": name,
            "birthdate": birthdate,
        }

        try:
            r = self.session.post(url, json=payload, headers=headers, timeout=30)

            if r.status_code == 200:
                self._log("账号创建成功")
                return True, "账号创建成功"
            else:
                error_msg = r.text[:200]
                self._log(f"创建失败: {r.status_code} - {error_msg}", "warning")
                return False, f"HTTP {r.status_code}"

        except Exception as e:
            self._log(f"创建异常: {e}", "error")
            return False, str(e)

    def _callback(self) -> bool:
        """完成注册回调"""
        self._log("执行回调...")
        url = f"{self.AUTH}/api/accounts/authorize/callback"
        try:
            r = self.session.get(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.AUTH}/about-you",
                },
                allow_redirects=True,
                timeout=30
            )
            return r.status_code == 200
        except Exception as e:
            self._log(f"回调失败: {e}", "warning")
            return False

    def _get_verification_code(self, timeout: int = 120) -> Optional[str]:
        """获取验证码"""
        try:
            self._log(f"正在等待邮箱 {self.email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=timeout,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )

            if code:
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _oauth_bootstrap(self) -> Tuple[bool, str]:
        """
        Bootstrap OAuth session - 确保获取 login_session cookie
        """
        self._log("Bootstrap OAuth session...")
        
        code_verifier, code_challenge = self._generate_pkce()
        state = secrets.token_urlsafe(32)
        
        authorize_params = {
            "response_type": "code",
            "client_id": self.oauth_manager.client_id,
            "redirect_uri": self.oauth_manager.redirect_uri,
            "scope": self.oauth_manager.scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        
        authorize_url = f"{self.AUTH}/oauth/authorize"
        
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        
        headers = {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Referer": "https://chatgpt.com/",
        }
        
        has_login_session = False
        authorize_final_url = ""
        
        try:
            r = self.session.get(
                authorize_url,
                params=authorize_params,
                headers=headers,
                allow_redirects=True,
                timeout=30
            )
            authorize_final_url = str(r.url)
            redirects = len(getattr(r, "history", []) or [])
            
            self._log(f"/oauth/authorize -> {r.status_code}, redirects={redirects}")
            
            has_login_session = any(
                (cookie.name if hasattr(cookie, 'name') else str(cookie)) == "login_session"
                for cookie in self.session.cookies
            )
            
            self._log(f"login_session: {'已获取' if has_login_session else '未获取'}")
            
        except Exception as e:
            self._log(f"/oauth/authorize 异常: {e}", "warning")
        
        if not has_login_session:
            self._log("未获取到 login_session，尝试 /api/oauth/oauth2/auth...")
            try:
                oauth2_url = f"{self.AUTH}/api/oauth/oauth2/auth"
                r = self.session.get(
                    oauth2_url,
                    params=authorize_params,
                    headers=headers,
                    allow_redirects=True,
                    timeout=30
                )
                authorize_final_url = str(r.url)
                
                has_login_session = any(
                    (cookie.name if hasattr(cookie, 'name') else str(cookie)) == "login_session"
                    for cookie in self.session.cookies
                )
                
                self._log(f"login_session(重试): {'已获取' if has_login_session else '未获取'}")
                
            except Exception as e:
                self._log(f"/api/oauth/oauth2/auth 异常: {e}", "warning")
        
        self.oauth_start = OAuthStart(
            auth_url=authorize_final_url or authorize_url,
            state=state,
            code_verifier=code_verifier,
            redirect_uri=self.oauth_manager.redirect_uri,
        )
        
        return has_login_session or bool(authorize_final_url), authorize_final_url

    def _generate_pkce(self) -> Tuple[str, str]:
        """生成 PKCE 参数"""
        import hashlib
        import base64
        
        code_verifier = secrets.token_urlsafe(64)
        challenge = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
        
        return code_verifier, code_challenge

    def _oauth_submit_email(self, email: str, continue_referer: str) -> Tuple[bool, Dict]:
        """OAuth 流程中提交邮箱"""
        self._log("POST /api/accounts/authorize/continue")
        
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="authorize_continue",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate, proxy_url=self.proxy_url
        )
        
        if not sentinel_token:
            self._log("无法获取 sentinel token (authorize_continue)", "warning")
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": continue_referer if continue_referer.startswith(self.AUTH) else f"{self.AUTH}/log-in",
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,
            "User-Agent": self.ua,
        }
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        headers.update(generate_datadog_trace())
        
        payload = {
            "username": {"kind": "email", "value": email},
        }
        
        try:
            r = self.session.post(
                f"{self.AUTH}/api/accounts/authorize/continue",
                json=payload,
                headers=headers,
                timeout=30,
                allow_redirects=False
            )
            
            self._log(f"/authorize/continue -> {r.status_code}")
            
            if r.status_code == 400 and "invalid_auth_step" in (r.text or ""):
                self._log("invalid_auth_step，重新 bootstrap...")
                return False, {"error": "invalid_auth_step", "need_retry": True}
            
            if r.status_code != 200:
                self._log(f"提交邮箱失败: {r.text[:180]}", "warning")
                return False, {"error": f"HTTP {r.status_code}"}
            
            data = r.json()
            continue_url = data.get("continue_url", "")
            page_type = data.get("page", {}).get("type", "")
            self._log(f"continue page={page_type or '-'} next={continue_url[:80] if continue_url else '-'}...")
            
            return True, data
            
        except Exception as e:
            self._log(f"提交邮箱异常: {e}", "error")
            return False, {"error": str(e)}

    def _oauth_verify_password(self, password: str) -> Tuple[bool, Dict]:
        """OAuth 流程中验证密码"""
        self._log("POST /api/accounts/password/verify")
        
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="password_verify",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate, proxy_url=self.proxy_url
        )
        
        if not sentinel_token:
            self._log("无法获取 sentinel token (password_verify)", "warning")
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/log-in/password",
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,
            "User-Agent": self.ua,
        }
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        headers.update(generate_datadog_trace())
        
        payload = {"password": password}
        
        try:
            r = self.session.post(
                f"{self.AUTH}/api/accounts/password/verify",
                json=payload,
                headers=headers,
                timeout=30,
                allow_redirects=False
            )
            
            self._log(f"/password/verify -> {r.status_code}")
            
            if r.status_code != 200:
                self._log(f"密码验证失败: {r.text[:180]}", "warning")
                return False, {"error": f"HTTP {r.status_code}"}
            
            data = r.json()
            continue_url = data.get("continue_url", "")
            page_type = data.get("page", {}).get("type", "")
            self._log(f"verify page={page_type or '-'} next={continue_url[:80] if continue_url else '-'}...")
            
            return True, data
            
        except Exception as e:
            self._log(f"密码验证异常: {e}", "error")
            return False, {"error": str(e)}

    def _extract_code_from_url(self, url: str) -> Optional[str]:
        """从 URL 中提取 code"""
        if not url or "code=" not in url:
            return None
        try:
            return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]
        except Exception:
            return None

    def _oauth_follow_for_code(self, start_url: str, referer: str = "", max_hops: int = 16) -> Tuple[Optional[str], str]:
        """跟随 URL 获取 authorization code"""
        if "code=" in start_url:
            code = self._extract_code_from_url(start_url)
            if code:
                return code, start_url
        
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }
        if referer:
            headers["Referer"] = referer
        
        current_url = start_url
        last_url = start_url
        
        for hop in range(max_hops):
            try:
                r = self.session.get(current_url, headers=headers, allow_redirects=False, timeout=30)
                last_url = str(r.url)
                self._log(f"follow[{hop+1}] {r.status_code} {last_url[:80]}")
                
            except Exception as e:
                import re
                maybe_localhost = re.search(r'(https?://localhost[^\s\'\"]+)', str(e))
                if maybe_localhost:
                    code = self._extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        self._log(f"从 localhost 异常提取到 code")
                        return code, maybe_localhost.group(1)
                self._log(f"follow[{hop+1}] 异常: {str(e)[:100]}", "warning")
                return None, last_url
            
            code = self._extract_code_from_url(last_url)
            if code:
                return code, last_url
            
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if not location:
                    return None, last_url
                
                if location.startswith("/"):
                    location = f"{self.AUTH}{location}"
                
                code = self._extract_code_from_url(location)
                if code:
                    return code, location
                
                current_url = location
                headers["Referer"] = last_url
            else:
                return None, last_url
        
        return None, last_url

    def _decode_oauth_session_cookie(self) -> Optional[Dict]:
        """解码 oai-client-auth-session cookie"""
        import base64
        
        def _decode_segment(raw):
            if not raw:
                return None
            try:
                padded = raw + "=" * ((4 - len(raw) % 4) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
                return json.loads(decoded)
            except Exception:
                return None

        try:
            for cookie in self.session.cookies:
                try:
                    name = cookie.name if hasattr(cookie, 'name') else str(cookie)
                    if name == "oai-client-auth-session":
                        value = cookie.value if hasattr(cookie, 'value') else self.session.cookies.get(name)
                        if value:
                            if "." in value:
                                first_segment = value.split(".", 1)[0]
                                data = _decode_segment(first_segment)
                                if data:
                                    return data

                            data = _decode_segment(value)
                            if data:
                                return data
                except Exception:
                    continue
        except Exception:
            pass
        
        return None

    def _oauth_submit_workspace_and_org(self, consent_url: str, max_retries: int = 3) -> Optional[str]:
        """提交 workspace 和 organization 选择"""
        session_data = None
        
        for attempt in range(max_retries):
            session_data = self._decode_oauth_session_cookie()
            if session_data:
                break
            
            if attempt < max_retries - 1:
                self._log(f"无法解码 oai-client-auth-session (尝试 {attempt + 1}/{max_retries})")
                time.sleep(0.3)
                
                try:
                    headers = {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "User-Agent": self.ua,
                        "Referer": f"{self.AUTH}/log-in/password",
                        "Upgrade-Insecure-Requests": "1",
                    }
                    r = self.session.get(consent_url, headers=headers, allow_redirects=True, timeout=30)
                    self._log(f"访问 consent 页面: {r.status_code}")
                    
                    for cookie in self.session.cookies:
                        name = cookie.name if hasattr(cookie, 'name') else str(cookie)
                        if "auth" in name.lower() or "session" in name.lower():
                            value = cookie.value if hasattr(cookie, 'value') else ""
                            self._log(f"Cookie: {name}={value[:30]}...")
                except Exception as e:
                    self._log(f"访问 consent 页面异常: {e}", "warning")
            else:
                self._log("无法解码 oai-client-auth-session，尝试直接提交 consent", "warning")
                return self._oauth_submit_consent_directly(consent_url)
        
        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            self._log("session 中没有 workspace 信息，尝试直接提交 consent", "warning")
            return self._oauth_submit_consent_directly(consent_url)
        
        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            self._log("workspace_id 为空", "warning")
            return None
        
        self._log(f"选择 workspace: {workspace_id}")
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.AUTH,
            "Referer": consent_url,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers.update(generate_datadog_trace())
        
        try:
            r = self.session.post(
                f"{self.AUTH}/api/accounts/workspace/select",
                json={"workspace_id": workspace_id},
                headers=headers,
                allow_redirects=False,
                timeout=30
            )
            
            self._log(f"workspace/select -> {r.status_code}")
            
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if location.startswith("/"):
                    location = f"{self.AUTH}{location}"
                if "code=" in location:
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 workspace/select 重定向获取到 code")
                        return code
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    orgs = data.get("data", {}).get("orgs", [])
                    continue_url = data.get("continue_url", "")
                    
                    if orgs:
                        org_id = (orgs[0] or {}).get("id")
                        projects = (orgs[0] or {}).get("projects", [])
                        project_id = (projects[0] or {}).get("id") if projects else None
                        
                        if org_id:
                            self._log(f"选择 organization: {org_id}")
                            
                            org_body = {"org_id": org_id}
                            if project_id:
                                org_body["project_id"] = project_id
                            
                            headers["Referer"] = continue_url if continue_url and continue_url.startswith("http") else consent_url
                            
                            r_org = self.session.post(
                                f"{self.AUTH}/api/accounts/organization/select",
                                json=org_body,
                                headers=headers,
                                allow_redirects=False,
                                timeout=30
                            )
                            
                            self._log(f"organization/select -> {r_org.status_code}")
                            
                            if r_org.status_code in (301, 302, 303, 307, 308):
                                location = r_org.headers.get("Location", "")
                                if location.startswith("/"):
                                    location = f"{self.AUTH}{location}"
                                if "code=" in location:
                                    code = self._extract_code_from_url(location)
                                    if code:
                                        self._log("从 organization/select 重定向获取到 code")
                                        return code
                            
                            if r_org.status_code == 200:
                                try:
                                    org_data = r_org.json()
                                    org_continue_url = org_data.get("continue_url", "")
                                    if org_continue_url:
                                        if org_continue_url.startswith("/"):
                                            org_continue_url = f"{self.AUTH}{org_continue_url}"
                                        code, _ = self._oauth_follow_for_code(org_continue_url, headers["Referer"])
                                        if code:
                                            return code
                                except Exception as e:
                                    self._log(f"解析 organization/select 响应异常: {e}", "warning")
                    
                    if continue_url:
                        if continue_url.startswith("/"):
                            continue_url = f"{self.AUTH}{continue_url}"
                        code, _ = self._oauth_follow_for_code(continue_url, headers["Referer"])
                        if code:
                            return code
                        
                except Exception as e:
                    self._log(f"处理 workspace/select 响应异常: {e}", "warning")
        
        except Exception as e:
            self._log(f"workspace/select 异常: {e}", "error")
        
        return None

    def _oauth_submit_consent_directly(self, consent_url: str) -> Optional[str]:
        """直接提交 consent（当没有 workspace 信息时的回退方案）"""
        self._log("尝试直接提交 consent...")
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.AUTH,
            "Referer": consent_url,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers.update(generate_datadog_trace())
        
        try:
            r = self.session.post(
                f"{self.AUTH}/api/accounts/consent",
                json={"scopes": ["openid", "profile", "email", "offline_access"]},
                headers=headers,
                allow_redirects=False,
                timeout=30
            )
            
            self._log(f"consent -> {r.status_code}")
            
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if location.startswith("/"):
                    location = f"{self.AUTH}{location}"
                if "code=" in location:
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 consent 重定向获取到 code")
                        return code
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    continue_url = data.get("continue_url", "")
                    if continue_url:
                        if continue_url.startswith("/"):
                            continue_url = f"{self.AUTH}{continue_url}"
                        code, _ = self._oauth_follow_for_code(continue_url, consent_url)
                        if code:
                            return code
                except Exception as e:
                    self._log(f"解析 consent 响应异常: {e}", "warning")
                    
        except Exception as e:
            self._log(f"直接提交 consent 异常: {e}", "error")
        
        return None

    def _oauth_get_tokens(self, code: str) -> Optional[Dict]:
        """用 authorization code 换取 tokens"""
        if not self.oauth_start:
            return None
        
        self._log("POST /oauth/token")
        
        url = f"{self.AUTH}/oauth/token"
        
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.oauth_manager.redirect_uri,
            "client_id": self.oauth_manager.client_id,
            "code_verifier": self.oauth_start.code_verifier,
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": self.ua,
        }
        
        try:
            r = self.session.post(url, data=payload, headers=headers, timeout=60)
            
            if r.status_code == 200:
                self._log("OAuth token 交换成功")
                return r.json()
            else:
                self._log(f"换取 tokens 失败: {r.status_code} - {r.text[:200]}", "error")
                
        except Exception as e:
            self._log(f"换取 tokens 异常: {e}", "error")
        
        return None

    def _oauth_handle_otp(self, continue_url: str) -> Tuple[bool, str]:
        """处理 OAuth 流程中的 OTP 验证"""
        self._log("检测到需要邮箱 OTP 验证")
        
        code = self._get_verification_code(timeout=60)
        if not code:
            return False, "未收到验证码"
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/email-verification",
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,
            "User-Agent": self.ua,
        }
        headers.update(generate_datadog_trace())
        
        try:
            r = self.session.post(
                f"{self.AUTH}/api/accounts/email-otp/validate",
                json={"code": code},
                headers=headers,
                timeout=30,
                allow_redirects=False
            )
            
            self._log(f"/email-otp/validate -> {r.status_code}")
            
            if r.status_code != 200:
                self._log(f"OTP 验证失败: {r.text[:160]}", "warning")
                return False, f"OTP 验证失败: HTTP {r.status_code}"
            
            data = r.json()
            new_continue_url = data.get("continue_url", "") or continue_url
            self._log("OTP 验证通过")
            return True, new_continue_url
            
        except Exception as e:
            self._log(f"OTP 验证异常: {e}", "error")
            return False, str(e)

    def run(self) -> RegistrationResult:
        """
        执行完整的注册流程
        
        Returns:
            RegistrationResult: 注册结果
        """
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._log("=" * 60)
            self._log("开始注册流程")
            self._log("=" * 60)

            # 1. 检查 IP 地理位置
            self._log("1. 检查 IP 地理位置...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            # 2. 创建邮箱
            self._log("2. 创建邮箱...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            # 3. 生成密码
            self.password = self._generate_password()
            self._log(f"3. 生成密码: {self.password}")
            result.password = self.password

            # 4. 访问首页
            self._log("4. 访问 ChatGPT 首页...")
            if not self._visit_homepage():
                result.error_message = "访问首页失败"
                return result

            # 5. 获取 CSRF token
            self._log("5. 获取 CSRF token...")
            csrf_token = self._get_csrf_token()
            if not csrf_token:
                result.error_message = "获取 CSRF token 失败"
                return result

            # 6. 提交邮箱
            self._log("6. 提交邮箱...")
            auth_url = self._signin_email(self.email, csrf_token)
            if not auth_url:
                result.error_message = "提交邮箱失败"
                return result

            # 7. 访问 authorize URL
            self._log("7. 访问 authorize URL...")
            final_url = self._authorize(auth_url)
            if not final_url:
                result.error_message = "Authorize 失败"
                return result

            final_path = urllib.parse.urlparse(final_url).path
            self._log(f"Authorize → {final_path}")

            # 8. 根据最终 URL 判断状态
            need_otp = False
            need_oauth_flow = False
            
            if "create-account/password" in final_path:
                self._log("全新注册流程")
                success, msg = self._register_user(self.email, self.password)
                if not success:
                    result.error_message = f"注册失败: {msg}"
                    return result
                self._send_email_otp()
                need_otp = True
                self._otp_sent_at = time.time()
                
            elif "email-verification" in final_path or "email-otp" in final_path:
                self._log("跳到 OTP 验证阶段（可能是已注册账号）")
                need_otp = True
                self._is_existing_account = True
                self._otp_sent_at = time.time()
                
            elif "about-you" in final_path:
                self._log("跳到填写信息阶段")
                user_info = generate_random_user_info()
                success, msg = self._create_account(
                    user_info["name"].split()[0] if " " in user_info["name"] else user_info["name"],
                    user_info["name"].split()[1] if " " in user_info["name"] else "",
                    user_info["birthdate"]
                )
                if not success:
                    result.error_message = f"创建账号失败: {msg}"
                    return result
                self._callback()
                need_oauth_flow = True
                
            elif "callback" in final_path or "chatgpt.com" in final_url:
                self._log("账号已完成注册，需要 OAuth 流程")
                need_oauth_flow = True
                
            else:
                self._log(f"未知跳转: {final_url}")
                success, msg = self._register_user(self.email, self.password)
                if not success:
                    result.error_message = f"注册失败: {msg}"
                    return result
                self._send_email_otp()
                need_otp = True
                self._otp_sent_at = time.time()

            # 9. 处理 OTP 验证
            if need_otp:
                self._log("8. 等待邮箱验证码...")
                otp_code = self._get_verification_code(timeout=120)
                if not otp_code:
                    result.error_message = "未收到验证码"
                    return result

                success, msg = self._verify_email_otp(otp_code)
                if not success:
                    result.error_message = f"验证码失败: {msg}"
                    return result

                # 10. 完成账号创建
                if not self._is_existing_account:
                    self._log("9. 完成账号创建...")
                    user_info = generate_random_user_info()
                    success, msg = self._create_account(
                        user_info["name"].split()[0] if " " in user_info["name"] else user_info["name"],
                        user_info["name"].split()[1] if " " in user_info["name"] else "",
                        user_info["birthdate"]
                    )
                    if not success:
                        result.error_message = f"创建账号失败: {msg}"
                        return result

                self._callback()
                need_oauth_flow = True

            # 11. OAuth 流程获取 tokens
            if need_oauth_flow:
                self._log("10. 开始 OAuth 流程...")
                
                # Bootstrap OAuth
                success, authorize_final_url = self._oauth_bootstrap()
                if not success:
                    result.error_message = "OAuth bootstrap 失败"
                    return result
                
                continue_referer = authorize_final_url if authorize_final_url.startswith(self.AUTH) else f"{self.AUTH}/log-in"
                
                # 提交邮箱
                success, email_data = self._oauth_submit_email(self.email, continue_referer)
                if not success:
                    if email_data.get("need_retry"):
                        # 重新 bootstrap
                        success, authorize_final_url = self._oauth_bootstrap()
                        if success:
                            continue_referer = authorize_final_url if authorize_final_url.startswith(self.AUTH) else f"{self.AUTH}/log-in"
                            success, email_data = self._oauth_submit_email(self.email, continue_referer)
                    
                    if not success:
                        result.error_message = f"OAuth 提交邮箱失败: {email_data.get('error', 'unknown')}"
                        return result
                
                continue_url = email_data.get("continue_url", "")
                page_type = email_data.get("page", {}).get("type", "")
                
                # 检查是否需要 OTP（已注册账号可能需要）
                need_oauth_otp = (
                    page_type == "email_otp_verification"
                    or "email-verification" in (continue_url or "")
                    or "email-otp" in (continue_url or "")
                )
                
                if need_oauth_otp:
                    success, continue_url = self._oauth_handle_otp(continue_url)
                    if not success:
                        result.error_message = f"OAuth OTP 验证失败: {continue_url}"
                        return result
                
                # 验证密码
                success, pwd_data = self._oauth_verify_password(self.password)
                if not success:
                    result.error_message = f"OAuth 密码验证失败: {pwd_data.get('error', 'unknown')}"
                    return result
                
                continue_url = pwd_data.get("continue_url", "") or continue_url
                page_type = pwd_data.get("page", {}).get("type", "") or page_type
                
                # 密码验证后再次检查是否需要 OTP
                need_oauth_otp_after_pwd = (
                    page_type == "email_otp_verification"
                    or "email-verification" in (continue_url or "")
                    or "email-otp" in (continue_url or "")
                )
                
                if need_oauth_otp_after_pwd:
                    self._log("密码验证后需要 OTP 验证")
                    success, continue_url = self._oauth_handle_otp(continue_url)
                    if not success:
                        result.error_message = f"OAuth OTP 验证失败: {continue_url}"
                        return result
                    # OTP 验证成功后更新 page_type
                    page_type = ""
                
                # 处理 consent 流程
                code = None
                consent_url = continue_url
                
                if consent_url and consent_url.startswith("/"):
                    consent_url = f"{self.AUTH}{consent_url}"
                
                if not consent_url and "consent" in page_type:
                    consent_url = f"{self.AUTH}/sign-in-with-chatgpt/codex/consent"
                
                if consent_url:
                    code = self._extract_code_from_url(consent_url)
                
                if not code and consent_url:
                    self._log("跟随 continue_url 提取 code...")
                    code, _ = self._oauth_follow_for_code(consent_url, referer=f"{self.AUTH}/log-in/password")
                
                consent_hint = (
                    ("consent" in (consent_url or ""))
                    or ("sign-in-with-chatgpt" in (consent_url or ""))
                    or ("workspace" in (consent_url or ""))
                    or ("organization" in (consent_url or ""))
                    or ("consent" in page_type)
                    or ("organization" in page_type)
                )
                
                if not code and consent_hint:
                    if not consent_url:
                        consent_url = f"{self.AUTH}/sign-in-with-chatgpt/codex/consent"
                    self._log("执行 workspace/org 选择...")
                    code = self._oauth_submit_workspace_and_org(consent_url)
                
                # 最后回退
                if not code:
                    fallback_consent = f"{self.AUTH}/sign-in-with-chatgpt/codex/consent"
                    for retry in range(3):
                        if retry > 0:
                            self._log(f"回退 consent 路径重试 (尝试 {retry + 1}/3)")
                            time.sleep(0.5)
                        
                        code = self._oauth_submit_workspace_and_org(fallback_consent)
                        if code:
                            break
                        
                        code, _ = self._oauth_follow_for_code(fallback_consent, referer=f"{self.AUTH}/log-in/password")
                        if code:
                            break
                
                if not code:
                    result.error_message = "未获取到 authorization code"
                    return result
                
                self._log(f"获取到 authorization code: {code[:20]}...")
                
                # 换取 tokens
                tokens = self._oauth_get_tokens(code)
                if not tokens:
                    result.error_message = "换取 tokens 失败"
                    return result
                
                result.access_token = tokens.get("access_token", "")
                result.refresh_token = tokens.get("refresh_token", "")
                result.id_token = tokens.get("id_token", "")
                
                # 解析 account_id
                import base64
                if result.id_token and result.id_token.count(".") >= 2:
                    try:
                        payload_b64 = result.id_token.split(".")[1]
                        pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
                        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
                        claims = json.loads(payload.decode("utf-8"))
                        auth_claims = claims.get("https://api.openai.com/auth") or {}
                        result.account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
                    except Exception:
                        pass

            # 获取 session_token
            session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
            if session_cookie:
                result.session_token = session_cookie
                self._log("获取到 Session Token")

            # 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功! (已注册账号)")
                result.source = "login"
            else:
                self._log("注册成功!")
                result.source = "register"
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log("=" * 60)

            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        try:
            settings = get_settings()

            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )

                self._log(f"账户已保存到数据库，ID: {account.id}")
                return True

        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
