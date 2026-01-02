"""
Authentication API Endpoints for Server-Side Session Management.

This module provides FastAPI endpoints for professional authentication:
- POST /api/auth/login - Authenticate and set HttpOnly cookie
- POST /api/auth/logout - Clear HttpOnly cookie
- GET /api/auth/me - Get current authenticated user

These endpoints work with the AuthMiddleware to provide true HttpOnly
cookie protection that JavaScript cannot access.

Usage:
    from reflex_local_auth import setup_auth_api

    app = rx.App()
    setup_auth_api(app)
"""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING, Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import select

if TYPE_CHECKING:
    from fastapi import FastAPI

from .middleware import (
    AUTH_COOKIE_HTTPONLY,
    AUTH_COOKIE_MAX_AGE,
    AUTH_COOKIE_NAME,
    AUTH_COOKIE_PATH,
    AUTH_COOKIE_SAMESITE,
    _config,
)

logger = logging.getLogger("reflex_local_auth")

# API Router for auth endpoints
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Request body for login endpoint."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Response body for successful login."""
    success: bool
    message: str
    user_id: Optional[int] = None
    username: Optional[str] = None


class UserResponse(BaseModel):
    """Response body for /me endpoint."""
    authenticated: bool
    user_id: Optional[int] = None
    username: Optional[str] = None
    enabled: Optional[bool] = None


def _create_session(user_id: int) -> Optional[str]:
    """Create a new auth session in the database.

    Args:
        user_id: The ID of the user to create a session for.

    Returns:
        The session ID if successful, None otherwise.
    """
    try:
        import reflex as rx
        from reflex.model import get_engine
        from sqlmodel import Session as DBSession

        from .auth_session import LocalAuthSession

        engine = get_engine()

        with DBSession(engine) as db_session:
            # Generate secure session ID
            import secrets
            session_id = secrets.token_urlsafe(32)

            # Create session with expiration
            expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                seconds=AUTH_COOKIE_MAX_AGE
            )

            auth_session = LocalAuthSession(
                user_id=user_id,
                session_id=session_id,
                expiration=expiration,
            )

            db_session.add(auth_session)
            db_session.commit()

            return session_id

    except Exception as e:
        logger.warning("Session creation error: %s", type(e).__name__)
        return None


def _validate_credentials(username: str, password: str) -> Optional[dict]:
    """Validate user credentials against the database.

    Args:
        username: The username to validate.
        password: The password to verify.

    Returns:
        User info dict if valid, None otherwise.
    """
    try:
        from reflex.model import get_engine
        from sqlmodel import Session as DBSession

        from .user import LocalUser

        engine = get_engine()

        with DBSession(engine) as db_session:
            user = db_session.exec(
                select(LocalUser).where(LocalUser.username == username)
            ).first()

            if user is None:
                return None

            if not user.enabled:
                return None

            if not user.verify(password):
                return None

            return {
                "id": user.id,
                "username": user.username,
                "enabled": user.enabled,
            }

    except Exception as e:
        logger.warning("Credential validation error: %s", type(e).__name__)
        return None


def _get_user_from_session(session_id: str) -> Optional[dict]:
    """Get user info from a valid session.

    Args:
        session_id: The session ID to look up.

    Returns:
        User info dict if valid session, None otherwise.
    """
    try:
        from reflex.model import get_engine
        from sqlmodel import Session as DBSession

        from .auth_session import LocalAuthSession
        from .user import LocalUser

        engine = get_engine()

        with DBSession(engine) as db_session:
            result = db_session.exec(
                select(LocalUser, LocalAuthSession).where(
                    LocalAuthSession.session_id == session_id,
                    LocalAuthSession.expiration >= datetime.datetime.now(datetime.timezone.utc),
                    LocalUser.id == LocalAuthSession.user_id,
                    LocalUser.enabled == True,
                )
            ).first()

            if result is None:
                return None

            user, session = result
            return {
                "id": user.id,
                "username": user.username,
                "enabled": user.enabled,
            }

    except Exception as e:
        logger.warning("Session lookup error: %s", type(e).__name__)
        return None


def _invalidate_session(session_id: str) -> bool:
    """Invalidate a session in the database.

    Args:
        session_id: The session ID to invalidate.

    Returns:
        True if successful, False otherwise.
    """
    try:
        from reflex.model import get_engine
        from sqlmodel import Session as DBSession

        from .auth_session import LocalAuthSession

        engine = get_engine()

        with DBSession(engine) as db_session:
            session = db_session.exec(
                select(LocalAuthSession).where(
                    LocalAuthSession.session_id == session_id
                )
            ).first()

            if session:
                db_session.delete(session)
                db_session.commit()

            return True

    except Exception as e:
        logger.warning("Session invalidation error: %s", type(e).__name__)
        return False


@auth_router.post("/login", response_model=LoginResponse)
async def login(request: Request, credentials: LoginRequest) -> Response:
    """Authenticate user and set HttpOnly session cookie.

    This endpoint validates credentials against the database and,
    if successful, sets an HttpOnly cookie that cannot be accessed
    by JavaScript, providing protection against XSS attacks.

    Args:
        request: The FastAPI request object.
        credentials: The login credentials (username, password).

    Returns:
        JSON response with success status and Set-Cookie header.
    """
    # Validate credentials
    user = _validate_credentials(credentials.username, credentials.password)

    if user is None:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "message": "Invalid username or password",
                "user_id": None,
                "username": None,
            }
        )

    # Create session
    session_id = _create_session(user["id"])

    if session_id is None:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Failed to create session",
                "user_id": None,
                "username": None,
            }
        )

    # Create response with HttpOnly cookie
    response = JSONResponse(
        content={
            "success": True,
            "message": "Login successful",
            "user_id": user["id"],
            "username": user["username"],
        }
    )

    # Set HttpOnly cookie
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=session_id,
        max_age=AUTH_COOKIE_MAX_AGE,
        path=AUTH_COOKIE_PATH,
        samesite=AUTH_COOKIE_SAMESITE,
        secure=_config.get("cookie_secure", False),
        httponly=AUTH_COOKIE_HTTPONLY,
    )

    logger.info("User %s logged in successfully", user["username"])

    return response


@auth_router.post("/logout")
async def logout(request: Request) -> Response:
    """Clear the session cookie and invalidate the session.

    This endpoint clears the HttpOnly cookie and removes the session
    from the database.

    Args:
        request: The FastAPI request object.

    Returns:
        JSON response with cleared cookie.
    """
    # Get session ID from cookie
    session_id = request.cookies.get(AUTH_COOKIE_NAME)

    # Invalidate session in database
    if session_id:
        _invalidate_session(session_id)

    # Create response
    response = JSONResponse(
        content={
            "success": True,
            "message": "Logout successful",
        }
    )

    # Clear the cookie
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path=AUTH_COOKIE_PATH,
    )

    logger.info("User logged out")

    return response


@auth_router.get("/me", response_model=UserResponse)
async def get_current_user(request: Request) -> Response:
    """Get the currently authenticated user.

    This endpoint checks the HttpOnly session cookie and returns
    the current user's information if authenticated.

    Args:
        request: The FastAPI request object.

    Returns:
        JSON response with user info or unauthenticated status.
    """
    # Get session ID from cookie
    session_id = request.cookies.get(AUTH_COOKIE_NAME)

    if not session_id:
        return JSONResponse(
            content={
                "authenticated": False,
                "user_id": None,
                "username": None,
                "enabled": None,
            }
        )

    # Look up user from session
    user = _get_user_from_session(session_id)

    if user is None:
        return JSONResponse(
            content={
                "authenticated": False,
                "user_id": None,
                "username": None,
                "enabled": None,
            }
        )

    return JSONResponse(
        content={
            "authenticated": True,
            "user_id": user["id"],
            "username": user["username"],
            "enabled": user["enabled"],
        }
    )


def setup_auth_api(app: "FastAPI") -> "FastAPI":
    """Set up the authentication API endpoints on a FastAPI app.

    This function adds the /api/auth/* endpoints to the given FastAPI
    application for handling authentication with HttpOnly cookies.

    Args:
        app: The FastAPI application to add endpoints to.

    Returns:
        The modified FastAPI application.

    Usage:
        from reflex_local_auth import setup_auth_api

        # In your Reflex app configuration
        app = rx.App(
            api_transformer=lambda api: setup_auth_api(api),
        )
    """
    app.include_router(auth_router)
    logger.info("Auth API endpoints registered at /api/auth/*")
    return app
