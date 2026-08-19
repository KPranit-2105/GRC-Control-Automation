from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import Identity
from app.seed_data import seed_database
from app.api.router import router as api_router
from app.api.dashboard import dashboard_router

app = FastAPI(
    title=settings.APP_NAME,
    description="Fictional GRC Engineering portfolio prototype demonstrating Privileged Access Review Control Automation.",
    version="1.0.0",
    debug=settings.DEBUG
)

@app.on_event("startup")
def startup_event():
    # Ensure database schema exists
    Base.metadata.create_all(bind=engine)
    
    # Auto-seed database if empty for instant local demonstration
    db = SessionLocal()
    try:
        count = db.query(Identity).count()
        if count == 0:
            print("Database empty. Seeding initial compliance test dataset...")
            seed_database()
    finally:
        db.close()

# Mount API routers
app.include_router(api_router)
app.include_router(dashboard_router)

@app.get("/")
def root():
    return RedirectResponse(url="/dashboard")
