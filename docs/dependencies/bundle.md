# Cookie Operations

When working with cookie-based authentication, you need access to the response object to set or unset cookies. AuthX methods accept a `response` parameter for this purpose.

## Basic Usage

```python
from fastapi import FastAPI, Response
from authx import AuthX, AuthXConfig

app = FastAPI()

config = AuthXConfig(
    JWT_SECRET_KEY="your-secret-key",
    JWT_TOKEN_LOCATION=["cookies"],
    JWT_COOKIE_SECURE=False,
)

auth = AuthX(config=config)
auth.handle_errors(app)


@app.post("/login")
def login(response: Response):
    token = auth.create_access_token(uid="user")
    auth.set_access_cookies(token, response)
    return {"message": "Logged in"}


@app.post("/logout", dependencies=[auth.ACCESS_REQUIRED])
def logout(response: Response):
    auth.unset_cookies(response)
    return {"message": "Logged out"}
```

## Complete Example

```python
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from authx import AuthX, AuthXConfig

app = FastAPI()

config = AuthXConfig(
    JWT_SECRET_KEY="your-secret-key",
    JWT_TOKEN_LOCATION=["cookies"],
    JWT_COOKIE_SECURE=False,  # Set True in production (HTTPS)
)

auth = AuthX(config=config)
auth.handle_errors(app)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(data: LoginRequest, response: Response):
    if data.username == "test" and data.password == "test":
        tokens = auth.create_token_pair(uid=data.username)
        auth.set_access_cookies(tokens.access_token, response)
        auth.set_refresh_cookies(tokens.refresh_token, response)
        return {"message": "Logged in"}
    raise HTTPException(401, detail="Invalid credentials")


@app.post("/refresh", dependencies=[auth.REFRESH_REQUIRED])
def refresh(payload=auth.REFRESH_REQUIRED, response: Response):
    access_token = auth.create_access_token(uid=payload.sub)
    auth.set_access_cookies(access_token, response)
    return {"message": "Token refreshed"}


@app.post("/logout", dependencies=[auth.ACCESS_REQUIRED])
def logout(response: Response):
    auth.unset_cookies(response)
    return {"message": "Logged out"}


@app.get("/protected", dependencies=[auth.ACCESS_REQUIRED])
def protected():
    return {"message": "Access granted"}
```

## Testing

```bash
# Login (sets cookies)
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"test", "password":"test"}' \
  -c cookies.txt \
  http://localhost:8000/login

# Access protected route (uses cookies)
curl -b cookies.txt http://localhost:8000/protected

# Logout (clears cookies)
curl -X POST -b cookies.txt -c cookies.txt http://localhost:8000/logout
```
