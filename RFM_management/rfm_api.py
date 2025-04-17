
from fastapi import FastAPI, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
import uvicorn
import os

from database_utils import RFMScore, get_db, create_db_and_tables, engine

# Create DB tables if they don't exist when the API starts
# NOTE: In production, use migrations (e.g., Alembic) instead of create_all on startup.
# This check prevents errors if the DB isn't ready when the API module loads.
if engine: # Check if engine was successfully created in database_utils
    create_db_and_tables()
else:
    print("[ERROR] API cannot start: Database engine not initialized. Cannot create/verify tables.")
    # Consider exiting or preventing FastAPI app creation if DB is essential

app = FastAPI(
    title="RFM Score Lookup API",
    description="Provides RFM scores for IP addresses based on batch processing.",
    version="1.0.1"
)

# Define a Pydantic response model for better validation and documentation
class RFMResponse(BaseModel):
    R: float = Field(..., description="Recency Score (1-5, higher is better)")
    F: float = Field(..., description="Frequency Score (1-5, higher is better)")
    M: float = Field(..., description="Monetary/Volume Score (1-5, higher is better)")
    composite_score: float | None = Field(None, description="Overall composite score")
    last_updated: str | None = Field(None, description="Timestamp (ISO format string) when the score was calculated")

    class Config:
        orm_mode = True # Enable reading data directly from ORM models

# --- API Endpoint for RFM Lookup ---
@app.get(
    "/rfm/{ip_address}",
    response_model=RFMResponse, # Use the Pydantic model for response structure
    tags=["RFM Lookup"],
    summary="Lookup RFM scores for a specific IP address",
    responses={
        200: {"description": "RFM scores found", "model": RFMResponse},
        404: {"description": "IP address not found in RFM database"},
        503: {"description": "Database not available"}, # Added for DB connection issues
    }
)
async def RFMlookup(
    ip_address: str = Path(..., description="The source IP address to look up", example="192.168.1.10"),
    db: Session = Depends(get_db) # Use the dependency injector from database_utils
):
    """
    Retrieves the calculated Recency, Frequency, and Monetary (RFM) scores
    for a given source IP address from the database populated by the batch processor.
    """
    print(f"Received lookup request for IP: {ip_address}")
    try:
        # Query the database using the SQLAlchemy session provided by Depends(get_db)
        score_data = db.query(RFMScore).filter(RFMScore.src_ip == ip_address).first()

        if score_data:
            print(f"Found scores for {ip_address}: R={score_data.r_score}, F={score_data.f_score}, M={score_data.m_score}")
            # Pydantic model will automatically map fields if names match
            return RFMResponse.from_orm(score_data) # Use from_orm for direct mapping
            # return RFMResponse(
            #     R=score_data.r_score,
            #     F=score_data.f_score,
            #     M=score_data.m_score,
            #     composite_score=score_data.composite_score,
            #     last_updated=score_data.last_updated
            # )
        else:
            print(f"IP address {ip_address} not found in RFM database.")
            raise HTTPException(
                status_code=404,
                detail=f"RFM scores not found for IP address: {ip_address}"
            )
    except Exception as e:
        # Catch potential database connection errors or other issues during query
        print(f"[ERROR] Database query failed for IP {ip_address}: {e}")
        raise HTTPException(
            status_code=503, # Service Unavailable
            detail="Could not connect to or query the RFM database."
        )


@app.get("/", tags=["Status"], summary="API Health Check")
async def read_root():
    """Basic health check endpoint to confirm the API is running."""
    return {"status": "RFM API is running"}

# --- How to Run (Instructions) ---
# This file is intended to be run with an ASGI server like Uvicorn within the Docker container.
# The Dockerfile and docker-compose.yml handle this.
#
# To run locally for development (after pip install -r requirements.txt):
# Ensure PostgreSQL is running (e.g., via docker-compose up db)
# Set environment variables (POSTGRES_USER, POSTGRES_PASSWORD, etc.) or use defaults.
# Run: uvicorn rfm_api:app --reload --host 0.0.0.0 --port 8000

if __name__ == "__main__":
     # This block allows running directly `python rfm_api.py` for simple testing,
     # but `uvicorn rfm_api:app --reload` is preferred for development.
     print("Starting Uvicorn server directly for RFM API...")
     print("Ensure DB is running and environment variables are set.")
     print("Access the API docs at http://localhost:8000/docs")
     # Get host/port from environment variables or use defaults
     api_host = os.getenv("API_HOST", "0.0.0.0")
     api_port = int(os.getenv("API_PORT", "8000"))
     uvicorn.run(app, host=api_host, port=api_port)
