INFO:     127.0.0.1:41701 - "POST /api/v1/auth/register HTTP/1.1" 201 Created
INFO:     127.0.0.1:65006 - "POST /api/v1/auth/register HTTP/1.1" 201 Created
INFO:     127.0.0.1:43809 - "POST /api/v1/auth/verify-email HTTP/1.1" 500 Internal Server Error
ERROR:    Exception in ASGI application
Traceback (most recent call last):
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\uvicorn\protocols\http\h11_impl.py", line 411, in run_asgi
    result = await app(  # type: ignore[func-returns-value]
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        self.scope, self.receive, self.send
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\uvicorn\middleware\proxy_headers.py", line 63, in __call__
    return await self.app(scope, receive, send)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\applications.py", line 1194, in __call__
    await super().__call__(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\applications.py", line 96, in __call__
    await self.middleware_stack(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\errors.py", line 186, in __call__
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\errors.py", line 164, in __call__
    await self.app(scope, receive, _send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\telemetry\_asgi.py", line 151, in __call__
    await self.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\exceptions.py", line 63, in __call__
    await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\middleware\asyncexitstack.py", line 18, in __call__
    await self.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\routing.py", line 683, in __call__
    await self.middleware_stack(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 2811, in app
    await route.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1839, in handle
    await self.original_router.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 2894, in handle
    await included_router._handle_selected(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1865, in _handle_selected
    await original_route.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1328, in handle
    await effective_context.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 166, in app
    await wrap_app_handling_exceptions(app, request)(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 152, in app
    response = await f(request)
               ^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 745, in app
    raw_response = await run_endpoint_function(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ...<3 lines>...
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 372, in run_endpoint_function
    return await dependant.call(**values)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\app\api\v1\auth.py", line 84, in verify_email
    result = await auth_service.verify_email(
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        email=payload.email, codigo=payload.codigo
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\app\services\auth_service.py", line 125, in verify_email
    await self._user_repo.mark_as_verified(user_id)
  File "D:\dev\AntFish-Backend\antfish-backend\app\repositories\mongo\user_repository.py", line 60, in mark_as_verified
    result = await self.collection.update_one(
                   ^^^^^^^^^^^^^^^
AttributeError: 'UserRepository' object has no attribute 'collection'. Did you mean: '_collection'?
INFO:     127.0.0.1:38024 - "POST /api/v1/auth/verify-email HTTP/1.1" 400 Bad Request
INFO:     127.0.0.1:42548 - "POST /api/v1/auth/verify-email HTTP/1.1" 400 Bad Request
INFO:     127.0.0.1:42548 - "POST /api/v1/auth/verify-email HTTP/1.1" 400 Bad Request
INFO:     127.0.0.1:32949 - "POST /api/v1/auth/verify-email HTTP/1.1" 500 Internal Server Error
ERROR:    Exception in ASGI application
Traceback (most recent call last):
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\uvicorn\protocols\http\h11_impl.py", line 411, in run_asgi
    result = await app(  # type: ignore[func-returns-value]
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        self.scope, self.receive, self.send
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\uvicorn\middleware\proxy_headers.py", line 63, in __call__
    return await self.app(scope, receive, send)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\applications.py", line 1194, in __call__
    await super().__call__(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\applications.py", line 96, in __call__
    await self.middleware_stack(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\errors.py", line 186, in __call__
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\errors.py", line 164, in __call__
    await self.app(scope, receive, _send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\telemetry\_asgi.py", line 151, in __call__
    await self.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\middleware\exceptions.py", line 63, in __call__
    await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\middleware\asyncexitstack.py", line 18, in __call__
    await self.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\routing.py", line 683, in __call__
    await self.middleware_stack(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 2811, in app
    await route.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1839, in handle
    await self.original_router.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 2894, in handle
    await included_router._handle_selected(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1865, in _handle_selected
    await original_route.handle(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 1328, in handle
    await effective_context.app(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 166, in app
    await wrap_app_handling_exceptions(app, request)(scope, receive, send)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 152, in app
    response = await f(request)
               ^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 745, in app
    raw_response = await run_endpoint_function(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ...<3 lines>...
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\venv\Lib\site-packages\fastapi\routing.py", line 372, in run_endpoint_function
    return await dependant.call(**values)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\dev\AntFish-Backend\antfish-backend\app\api\v1\auth.py", line 84, in verify_email
    result = await auth_service.verify_email(
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        email=payload.email, codigo=payload.codigo
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "D:\dev\AntFish-Backend\antfish-backend\app\services\auth_service.py", line 125, in verify_email
    await self._user_repo.mark_as_verified(user_id)
  File "D:\dev\AntFish-Backend\antfish-backend\app\repositories\mongo\user_repository.py", line 60, in mark_as_verified
    result = await self.collection.update_one(
                   ^^^^^^^^^^^^^^^
AttributeError: 'UserRepository' object has no attribute 'collection'. Did you mean: '_collection'?  
INFO:     127.0.0.1:45354 - "POST /api/v1/auth/verify-email HTTP/1.1" 400 Bad Request
