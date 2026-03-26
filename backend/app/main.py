"""
QuantumShield v3.0 — Main FastAPI Application
Includes DB init, default admin seeding, and all routers.
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, SessionLocal, Base
from app.routers import scanner, reports, health, auth as auth_router, ai as ai_router
from app.routers import api_scanner as api_scanner_router

app = FastAPI(
    title="QuantumShield PQC Scanner API",
    description="Cryptographic Bill of Materials & Post-Quantum Cryptography Readiness Scanner",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router,              prefix="/api/v1", tags=["Health"])
app.include_router(auth_router.router,         tags=["Authentication"])
app.include_router(scanner.router,             prefix="/api/v1", tags=["Scanner"])
app.include_router(reports.router,             tags=["Reports"])
app.include_router(ai_router.router,           tags=["AI"])
app.include_router(api_scanner_router.router,  tags=["API Scanner", "VPN", "Export"])


@app.on_event("startup")
def startup():
    """Create all tables and seed the default admin user if none exists."""
    # Import models so SQLAlchemy can see them
    from app.models.user import User
    from app.models.scan_history import ScanHistory
    from app.routers.auth import hash_password

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin_password = os.getenv("ADMIN_PASSWORD", "quantum2026")
            admin = User(
                username="admin",
                email="admin@quantumshield.io",
                hashed_password=hash_password(admin_password),
                role="Admin",
                is_active=True,
            )
            # Seed demo users
            operator = User(
                username="pnb",
                email="operator@pnbindia.in",
                hashed_password=hash_password("pnbsecure"),
                role="Operator",
                is_active=True,
            )
            checker = User(
                username="auditor",
                email="auditor@quantumshield.io",
                hashed_password=hash_password("audit2026"),
                role="Checker",
                is_active=True,
            )
            db.add_all([admin, operator, checker])
            db.commit()
            print("✅ Database seeded — admin / pnb / auditor users created")
        else:
            print("✅ Database ready — existing users found")
    except Exception as e:
        print(f"⚠ Startup DB seed error: {e}")
        db.rollback()
    finally:
        db.close()


@app.get("/")
def root():
    return {
        "service": "QuantumShield PQC Scanner",
        "version": "3.0.0",
        "status": "operational",
        "docs": "/docs",
    }
