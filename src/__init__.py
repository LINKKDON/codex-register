"""
OpenAI/Codex CLI 自动注册系统
"""

from .config import get_settings, EmailServiceType
from .database import get_db, Account, EmailService, RegistrationTask
from .core import RegistrationEngine, RegistrationResult
from .services import EmailServiceFactory, BaseEmailService

__version__ = "2.0.0"
__author__ = "Yasal"

__all__ = [
    'get_settings',
    'EmailServiceType',
    'get_db',
    'Account',
    'EmailService',
    'RegistrationTask',
    'RegistrationEngine',
    'RegistrationResult',
    'EmailServiceFactory',
    'BaseEmailService',
]
