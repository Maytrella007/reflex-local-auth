from . import pages, routes
from .local_auth import LocalAuthState
from .login import LoginState, require_login
from .middleware import (
    AuthMiddleware,
    configure_middleware,
    set_auth_cookie,
    clear_auth_cookie,
    is_safe_redirect_url,
)
from .registration import RegistrationState
from .routes import set_login_route, set_register_route
from .user import LocalUser

__all__ = [
    # Auth State
    "LocalAuthState",
    "LocalUser",
    "LoginState",
    "RegistrationState",
    # Middleware (new)
    "AuthMiddleware",
    "configure_middleware",
    "set_auth_cookie",
    "clear_auth_cookie",
    "is_safe_redirect_url",
    # Pages and Routes
    "pages",
    "require_login",
    "routes",
    "set_login_route",
    "set_register_route",
]
