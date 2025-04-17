
import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.sql import func # For potential default timestamps
import datetime

# --- Database Configuration ---
# Read connection details from environment variables
DB_NAME = os.getenv('POSTGRES_DB', 'mydatabase')
DB_USER = os.getenv('POSTGRES_USER', 'user')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password')
DB_HOST = os.getenv('POSTGRES_HOST', 'db')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')

# --- SQLAlchemy Setup ---
SQLALCHEMY_DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True) # pool_pre_ping checks connections
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    print("SQLAlchemy engine and session configured successfully.")
except Exception as e:
    print(f"[ERROR] Failed to create SQLAlchemy engine: {e}")
    # Depending on usage, might want to exit or handle this more gracefully
    engine = None
    SessionLocal = None
    Base = None

# --- Database Model (using SQLAlchemy Base) ---
class RFMScore(Base):
    """SQLAlchemy model for storing RFM scores."""
    __tablename__ = "rfm_scores" # Ensure this matches Spark's target table

    src_ip = Column(String, primary_key=True, index=True)
    r_score = Column(Float, nullable=False)
    f_score = Column(Float, nullable=False)
    m_score = Column(Float, nullable=False)
    composite_score = Column(Float, nullable=True) # Added composite score
    # Store last_updated as String (ISO format) to simplify Spark JDBC write
    last_updated = Column(String, nullable=False)
    # Alternatively, use DateTime:
    # last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# --- Dependency for FastAPI ---
def get_db():
    """Dependency generator for getting a SQLAlchemy DB session."""
    if SessionLocal is None:
        raise RuntimeError("Database session factory (SessionLocal) is not initialized.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Function to Create Tables ---
def create_db_and_tables():
    """Creates database tables based on SQLAlchemy models."""
    if engine is None or Base is None:
        print("[ERROR] Cannot create tables: SQLAlchemy engine or Base not initialized.")
        return
    try:
        print(f"Attempting to create tables defined in Base metadata on engine: {engine.url}")
        # Check connection before trying to create tables
        with engine.connect() as connection:
             print("Database connection successful for table creation.")
        Base.metadata.create_all(bind=engine)
        print(f"Tables (including '{RFMScore.__tablename__}') created or verified successfully.")
    except Exception as e:
        print(f"[ERROR] Could not create tables: {e}")
        print("Please ensure the database container is running, accessible, and permissions are correct.")
        # Consider raising the exception if table creation is critical at startup

# --- JDBC Helper Functions for Spark ---
def get_jdbc_url():
    """Constructs the JDBC URL for Spark."""
    # Note: Spark JDBC URL format is slightly different from SQLAlchemy
    return f"jdbc:postgresql://{DB_HOST}:{DB_PORT}/{DB_NAME}"

def get_jdbc_properties():
    """Returns a dictionary of properties needed for Spark JDBC connection."""
    return {
        "user": DB_USER,
        "password": DB_PASSWORD,
        "driver": "org.postgresql.Driver" # Standard PostgreSQL JDBC driver class
    }

# --- Direct psycopg2 Functions (Kept for potential other uses) ---

def get_db_connection():
    """
    Establishes a direct psycopg2 connection to the PostgreSQL database.
    """
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        # print(f"Direct psycopg2 connection successful to {DB_HOST}:{DB_PORT}") # Less verbose
        return conn
    except psycopg2.OperationalError as e:
        print(f"Error connecting (psycopg2): {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during direct connection: {e}")
        return None

@contextmanager
def managed_cursor(commit=False, use_dict_cursor=True):
    """Context manager for handling direct psycopg2 cursors and connections."""
    conn = get_db_connection()
    if conn is None:
        raise ConnectionError("Failed to establish direct database connection.")

    cursor_factory = psycopg2.extras.RealDictCursor if use_dict_cursor else None
    cursor = conn.cursor(cursor_factory=cursor_factory)

    try:
        yield cursor
        if commit:
            conn.commit()
            # print("Transaction committed (psycopg2).")
    except (Exception, psycopg2.Error) as e:
        print(f"Direct DB Error: {e}")
        conn.rollback()
        # print("Transaction rolled back (psycopg2).")
        raise
    finally:
        cursor.close()
        conn.close()
        # print("Direct database connection closed (psycopg2).")
