"""Pruebas unitarias para el flujo de Login de Usuario (RF-06.8, D12)."""

from unittest.mock import AsyncMock
from bson import ObjectId
from fastapi import FastAPI, status
import httpx
import pytest

from app.api.v1 import auth
from app.core.exceptions import AccountNotVerifiedError, UnauthorizedError
from app.core.security import decode_access_token, decode_refresh_token, hash_password
from app.services.auth_service import AuthService


@pytest.fixture
def mock_user_repo():
    return AsyncMock()


@pytest.fixture
def mock_verification_service():
    return AsyncMock()


@pytest.fixture
def auth_service(mock_user_repo, mock_verification_service):
    return AuthService(
        user_repository=mock_user_repo,
        verification_service=mock_verification_service,
    )


@pytest.fixture
def test_app(auth_service):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    # Inyectar container simulado con auth_service en app.state
    class DummyContainer:
        def __init__(self, service):
            self.auth_service = service

    app.state.container = DummyContainer(auth_service)
    return app


@pytest.mark.asyncio
async def test_login_successful_active_account(auth_service, mock_user_repo):
    """Verifica que un usuario activo con credenciales correctas obtenga tokens JWT válidos."""
    user_id = ObjectId()
    plain_password = "PasswordSeguro123!"
    hashed = hash_password(plain_password)

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "nombre": "Carlos Ramírez",
        "password_hash": hashed,
        "estado_cuenta": "activa",
        "email_verificado": True,
    }

    result = await auth_service.authenticate_user("carlos@correo.com", plain_password)

    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"

    # Verificar claims de los tokens JWT decodificados
    access_claims = decode_access_token(result["access_token"])
    assert access_claims["sub"] == str(user_id)
    assert access_claims["email"] == "carlos@correo.com"
    assert access_claims["type"] == "access"
    assert "exp" in access_claims
    assert "iat" in access_claims

    refresh_claims = decode_refresh_token(result["refresh_token"])
    assert refresh_claims["sub"] == str(user_id)
    assert refresh_claims["email"] == "carlos@correo.com"
    assert refresh_claims["type"] == "refresh"
    assert "exp" in refresh_claims
    assert "iat" in refresh_claims


@pytest.mark.asyncio
async def test_login_pending_verification_returns_403(auth_service, mock_user_repo):
    """Verifica que si la contraseña es válida pero la cuenta está pendiente, lance AccountNotVerifiedError (403)."""
    user_id = ObjectId()
    plain_password = "PasswordSeguro123!"
    hashed = hash_password(plain_password)

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "password_hash": hashed,
        "estado_cuenta": "pendiente_verificacion",
        "email_verificado": False,
    }

    with pytest.raises(AccountNotVerifiedError) as exc_info:
        await auth_service.authenticate_user("carlos@correo.com", plain_password)

    assert "ACCOUNT_NOT_VERIFIED" in str(exc_info.value)


@pytest.mark.asyncio
async def test_login_invalid_password_returns_401(auth_service, mock_user_repo):
    """Verifica que una contraseña incorrecta lance UnauthorizedError (401)."""
    user_id = ObjectId()
    hashed = hash_password("PasswordSeguro123!")

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "password_hash": hashed,
        "estado_cuenta": "activa",
        "email_verificado": True,
    }

    with pytest.raises(UnauthorizedError) as exc_info:
        await auth_service.authenticate_user("carlos@correo.com", "PasswordErronea123!")

    assert "Credenciales inválidas" in str(exc_info.value)


@pytest.mark.asyncio
async def test_login_non_existent_email_returns_401(auth_service, mock_user_repo):
    """Verifica que si el correo no existe lance UnauthorizedError (401)."""
    mock_user_repo.find_by_email.return_value = None

    with pytest.raises(UnauthorizedError) as exc_info:
        await auth_service.authenticate_user("noexiste@correo.com", "PasswordSeguro123!")

    assert "Credenciales inválidas" in str(exc_info.value)


@pytest.mark.asyncio
async def test_login_user_without_password_hash_returns_401(auth_service, mock_user_repo):
    """Verifica que una cuenta federada sin password_hash lance UnauthorizedError (401)."""
    user_id = ObjectId()
    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "googleuser@gmail.com",
        "password_hash": None,
        "proveedor_auth": "google",
        "estado_cuenta": "activa",
    }

    with pytest.raises(UnauthorizedError) as exc_info:
        await auth_service.authenticate_user("googleuser@gmail.com", "cualquiera123")

    assert "Credenciales inválidas" in str(exc_info.value)


@pytest.mark.asyncio
async def test_endpoint_login_success(test_app, mock_user_repo):
    """Verifica la respuesta HTTP 200 del endpoint POST /api/v1/auth/login."""
    user_id = ObjectId()
    plain_password = "PasswordSeguro123!"
    hashed = hash_password(plain_password)

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "nombre": "Carlos Ramírez",
        "password_hash": hashed,
        "estado_cuenta": "activa",
        "email_verificado": True,
    }

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "carlos@correo.com", "password": plain_password},
        )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_endpoint_login_pending_verification_returns_403(test_app, mock_user_repo):
    """Verifica que el endpoint devuelva HTTP 403 cuando la cuenta esté pendiente_verificacion."""
    user_id = ObjectId()
    plain_password = "PasswordSeguro123!"
    hashed = hash_password(plain_password)

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "password_hash": hashed,
        "estado_cuenta": "pendiente_verificacion",
        "email_verificado": False,
    }

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "carlos@correo.com", "password": plain_password},
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "ACCOUNT_NOT_VERIFIED" in response.json()["detail"]


@pytest.mark.asyncio
async def test_endpoint_login_invalid_password_returns_401(test_app, mock_user_repo):
    """Verifica que el endpoint devuelva HTTP 401 si la contraseña no coincide."""
    user_id = ObjectId()
    hashed = hash_password("PasswordSeguro123!")

    mock_user_repo.find_by_email.return_value = {
        "_id": user_id,
        "email": "carlos@correo.com",
        "password_hash": hashed,
        "estado_cuenta": "activa",
        "email_verificado": True,
    }

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "carlos@correo.com", "password": "BadPassword123!"},
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
