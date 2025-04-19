
import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, String, Float, DateTime, ForeignKey, Integer, Boolean # Added Integer, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.sql import func
import datetime

# --- Database Configuration ---
DB_NAME = os.getenv('POSTGRES_DB', 'mydatabase')
DB_USER = os.getenv('POSTGRES_USER', 'user')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password')
DB_HOST = os.getenv('POSTGRES_HOST', 'db')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')

# --- SQLAlchemy Setup ---
SQLALCHEMY_DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    print("SQLAlchemy engine and session configured successfully.")
except Exception as e:
    print(f"[ERROR] Failed to create SQLAlchemy engine: {e}")
    engine = None
    SessionLocal = None
    Base = None

# --- Database Models ---

class RFMScore(Base):
    __tablename__ = "rfm_scores"
    src_ip = Column(String, primary_key=True, index=True)
    r_score = Column(Float, nullable=False)
    f_score = Column(Float, nullable=False)
    m_score = Column(Float, nullable=False)
    composite_score = Column(Float, nullable=True)
    last_updated = Column(String, nullable=False)
    # Optional: Add a relationship if you have a User table
    # user_email = Column(String, ForeignKey('users.email'))

# --- Dependency for FastAPI ---
def get_db():
    if SessionLocal is None:
        raise RuntimeError("Database session factory (SessionLocal) is not initialized.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Function to Create Tables ---
def create_db_and_tables():
    if engine is None or Base is None:
        print("[ERROR] Cannot create tables: SQLAlchemy engine or Base not initialized.")
        return
    try:
        print(f"Attempting to create tables defined in Base metadata on engine: {engine.url}")
        with engine.connect() as connection:
             print("Database connection successful for table creation.")
        Base.metadata.create_all(bind=engine)
        print(f"Tables (including '{RFMScore.__tablename__}', created or verified.")
    except Exception as e:
        print(f"[ERROR] Could not create tables: {e}")

# --- JDBC Helper Functions ---
def get_jdbc_url():
    return f"jdbc:postgresql://{DB_HOST}:{DB_PORT}/{DB_NAME}"

def get_jdbc_properties():
    return {
        "user": DB_USER,
        "password": DB_PASSWORD,
        "driver": "org.postgresql.Driver"
    }

# --- Direct psycopg2 Functions (Keep Existing, optional) ---
# ... (get_db_connection, managed_cursor) ...
if __name__ == "__main__":
    create_db_and_tables()