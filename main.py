
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt


app = FastAPI()

# Exact values provided by the assignment
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-af6q6itt.apps.exam.local"

# Public key supplied by the assignment.
# Keep the BEGIN/END lines and the key contents exactly as given.
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


# Define the JSON body expected by POST /verify
class VerifyRequest(BaseModel):
    token: str


@app.post("/verify")
def verify_token(request: VerifyRequest):
    try:
        # Verify the signature and required claims.
        # Only RS256 is accepted.
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "email", "sub"]
            },
        )

        # The assignment requires aud to equal the exact string.
        # This rejects an audience list or a different audience value.
        if claims["aud"] != AUDIENCE:
            return JSONResponse(
                status_code=401,
                content={"valid": False},
            )

        # Return actual claims from the verified token.
        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }

    except (jwt.PyJWTError, TypeError, ValueError):
        # Malformed, expired, tampered, or otherwise invalid JWT
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
