"""
QuantumShield — Authentication Router
JWT-based auth, bcrypt passwords, role-based access (Admin / Operator / Checker).
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User

SECRET_KEY  = os.getenv("SECRET_KEY", "qs-super-secret-2026-please-change-in-production")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
router        = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type:   str
    role:         str
    username:     str
    email:        str
    user_id:      int

class UserCreate(BaseModel):
    username: str
    email:    str
    password: str
    role:     str = "Operator"

class UserResponse(BaseModel):
    id:         int
    username:   str
    email:      str
    role:       str
    is_active:  bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True

class ChangePassword(BaseModel):
    current_password: str
    new_password:     str

class UpdateRole(BaseModel):
    role: str


# ── Utility Functions ─────────────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────────
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token — please log in again",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise exc
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is disabled. Contact your administrator.")
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return Token(access_token=token, token_type="bearer",
                 role=user.role, username=user.username,
                 email=user.email, user_id=user.id)

@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db),
             admin: User = Depends(require_admin)):
    """Only Admins can create new users."""
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if user_data.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Role must be Admin, Operator, or Checker")

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role=user_data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.created_at.desc()).all()

@router.put("/users/{user_id}/toggle", response_model=UserResponse)
def toggle_user(user_id: int, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == admin.username:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    user.is_active = not user.is_active
    db.commit()
    db.refresh(user)
    return user

@router.put("/users/{user_id}/role", response_model=UserResponse)
def update_role(user_id: int, body: UpdateRole, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role not in ("Admin", "Operator", "Checker"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user.role = body.role
    db.commit()
    db.refresh(user)
    return user

@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == admin.username:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    db.delete(user)
    db.commit()
    return {"message": f"User '{user.username}' deleted"}

@router.post("/change-password")
def change_password(data: ChangePassword, current_user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}
