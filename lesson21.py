
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel
from database import Base, engine

Base.metadata.create_all(bind=engine)

# ==================================================
# ⚙️ CONFIG
# ==================================================

SECRET_KEY = "hdjshhf"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 70

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="JWT Auth with Logout")

# ==================================================
# 🧠 Fake DB
# ==================================================

users_db = {}
refresh_token_blacklist = set()

# ==================================================
# 📦 SCHEMAS
# ==================================================

class User(BaseModel):
    email: str
    role: str = "user"

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# ==================================================
# 🔐 UTILS
# ==================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + expires_delta
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==================================================
# 🔑 AUTH HELPERS
# ==================================================

def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email not in users_db:
            raise HTTPException(status_code=401)
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user

# ==================================================
# 🚀 ROUTES
# ==================================================

@app.post("/register")
def register(email: str, password: str):
    if email in users_db:
        raise HTTPException(status_code=400, detail="User exists")

    users_db[email] = UserInDB(
        email=email,
        role="user",
        hashed_password=hash_password(password)
    )

    return {"message": "User registered"}

# --------------------------------------------------

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_token(
        {"sub": user.email, "role": user.role},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    refresh_token = create_token(
        {"sub": user.email, "type": "refresh"},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

# --------------------------------------------------

@app.post("/refresh", response_model=Token)
def refresh_token(refresh_token: str):
    if refresh_token in refresh_token_blacklist:
        raise HTTPException(status_code=401, detail="Token revoked")

    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401)

        email = payload.get("sub")

        access_token = create_token(
            {"sub": email},
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        new_refresh_token = create_token(
            {"sub": email, "type": "refresh"},
            timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# --------------------------------------------------
# 🚪 LOGOUT
# --------------------------------------------------

@app.post("/logout")
def logout(refresh_token: str):
    """
    Logout = заносимо refresh token в blacklist
    """
    refresh_token_blacklist.add(refresh_token)
    return {"message": "Logged out successfully"}

# --------------------------------------------------
# 🔒 PROTECTED
# --------------------------------------------------

@app.get("/profile")
def profile(user: User = Depends(get_current_user)):
    return user

@app.get("/admin")
def admin_panel(user: User = Depends(require_admin)):
    return {"message": "Welcome admin"}
