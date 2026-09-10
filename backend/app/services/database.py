from sqlalchemy import create_engine, Column, Integer, String, Float, Index
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
import os

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

SQL_DB_URL = "sqlite:///./data/sentinel.db"

engine = create_engine(
    SQL_DB_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class RiskEventModel(Base):
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, index=True)
    domain_hash = Column(String, index=True)
    timestamp = Column(Integer) # Unix timestamp
    risk_score = Column(Float)
    primary_label = Column(String)
    action = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
