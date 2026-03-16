"""
支付相关 API 路由
"""

import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...database.session import get_db
from ...database.models import Account
from ...config.settings import get_settings
from .accounts import resolve_account_ids
from ...core.payment import (
    generate_plus_link,
    generate_team_link,
    open_url_incognito,
    check_subscription_status,
)
from ...core.team_manager import (
    upload_to_team_manager,
    batch_upload_to_team_manager,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ============== Pydantic Models ==============

class GenerateLinkRequest(BaseModel):
    account_id: int
    plan_type: str  # 'plus' or 'team'
    workspace_name: str = "MyTeam"
    price_interval: str = "month"
    seat_quantity: int = 5
    proxy: Optional[str] = None
    auto_open: bool = False  # 生成后是否自动无痕打开


class OpenIncognitoRequest(BaseModel):
    url: str


class MarkSubscriptionRequest(BaseModel):
    subscription_type: str  # 'free' / 'plus' / 'team'


class BatchCheckSubscriptionRequest(BaseModel):
    ids: List[int] = []
    proxy: Optional[str] = None
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None


class UploadTMRequest(BaseModel):
    proxy: Optional[str] = None  # 保留，TM 上传不走代理


class BatchUploadTMRequest(BaseModel):
    ids: List[int] = []
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None


# ============== 支付链接生成 ==============

@router.post("/generate-link")
def generate_payment_link(request: GenerateLinkRequest):
    """生成 Plus 或 Team 支付链接，可选自动无痕打开"""
    with get_db() as db:
        account = db.query(Account).filter(Account.id == request.account_id).first()
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")

        proxy = request.proxy or get_settings().proxy_url

        try:
            if request.plan_type == "plus":
                link = generate_plus_link(account, proxy)
            elif request.plan_type == "team":
                link = generate_team_link(
                    account,
                    workspace_name=request.workspace_name,
                    price_interval=request.price_interval,
                    seat_quantity=request.seat_quantity,
                    proxy=proxy,
                )
            else:
                raise HTTPException(status_code=400, detail="plan_type 必须为 plus 或 team")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"生成支付链接失败: {e}")
            raise HTTPException(status_code=500, detail=f"生成链接失败: {str(e)}")

    opened = False
    if request.auto_open and link:
        opened = open_url_incognito(link)

    return {
        "success": True,
        "link": link,
        "plan_type": request.plan_type,
        "auto_opened": opened,
    }


@router.post("/open-incognito")
def open_browser_incognito(request: OpenIncognitoRequest):
    """后端命令行以无痕模式打开指定 URL"""
    if not request.url:
        raise HTTPException(status_code=400, detail="URL 不能为空")
    success = open_url_incognito(request.url)
    if success:
        return {"success": True, "message": "已在无痕模式打开浏览器"}
    return {"success": False, "message": "未找到可用的 Chrome/Edge，请手动复制链接"}


# ============== 订阅状态 ==============

@router.post("/accounts/{account_id}/mark-subscription")
def mark_subscription(account_id: int, request: MarkSubscriptionRequest):
    """手动标记账号订阅类型"""
    allowed = ("free", "plus", "team")
    if request.subscription_type not in allowed:
        raise HTTPException(status_code=400, detail=f"subscription_type 必须为 {allowed}")

    with get_db() as db:
        account = db.query(Account).filter(Account.id == account_id).first()
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")

        account.subscription_type = None if request.subscription_type == "free" else request.subscription_type
        account.subscription_at = datetime.utcnow() if request.subscription_type != "free" else None
        db.commit()

    return {"success": True, "subscription_type": request.subscription_type}


@router.post("/accounts/batch-check-subscription")
def batch_check_subscription(request: BatchCheckSubscriptionRequest):
    """批量检测账号订阅状态"""
    proxy = request.proxy or get_settings().proxy_url

    results = {"success_count": 0, "failed_count": 0, "details": []}

    with get_db() as db:
        ids = resolve_account_ids(
            db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter
        )
        for account_id in ids:
            account = db.query(Account).filter(Account.id == account_id).first()
            if not account:
                results["failed_count"] += 1
                results["details"].append(
                    {"id": account_id, "email": None, "success": False, "error": "账号不存在"}
                )
                continue

            try:
                status = check_subscription_status(account, proxy)
                account.subscription_type = None if status == "free" else status
                account.subscription_at = datetime.utcnow() if status != "free" else account.subscription_at
                db.commit()
                results["success_count"] += 1
                results["details"].append(
                    {"id": account_id, "email": account.email, "success": True, "subscription_type": status}
                )
            except Exception as e:
                results["failed_count"] += 1
                results["details"].append(
                    {"id": account_id, "email": account.email, "success": False, "error": str(e)}
                )

    return results


# ============== Team Manager 上传 ==============

@router.post("/accounts/{account_id}/upload-tm")
def upload_account_tm(account_id: int, request: UploadTMRequest = None):
    """上传单账号到 Team Manager"""
    settings = get_settings()
    if not settings.tm_enabled:
        raise HTTPException(status_code=400, detail="Team Manager 上传未启用")

    api_url = settings.tm_api_url
    api_key = settings.tm_api_key.get_secret_value() if settings.tm_api_key else ""

    with get_db() as db:
        account = db.query(Account).filter(Account.id == account_id).first()
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        success, message = upload_to_team_manager(account, api_url, api_key)

    return {"success": success, "message": message}


@router.post("/accounts/batch-upload-tm")
def batch_upload_tm(request: BatchUploadTMRequest):
    """批量上传账号到 Team Manager"""
    settings = get_settings()
    if not settings.tm_enabled:
        raise HTTPException(status_code=400, detail="Team Manager 上传未启用")

    api_url = settings.tm_api_url
    api_key = settings.tm_api_key.get_secret_value() if settings.tm_api_key else ""

    with get_db() as db:
        ids = resolve_account_ids(
            db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter
        )

    results = batch_upload_to_team_manager(ids, api_url, api_key)
    return results
