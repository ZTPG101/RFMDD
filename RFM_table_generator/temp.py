"""
network_rfm_batch.py
--------------------

Scheduled batch job that **only looks at network‑log rows created since the
previous run**, recalculates **R F M scores per source‑IP** (with *pkt_len* as
the Monetary value), and persists the updated table to **CSV**.

➤ HOW TO SCHEDULE  
  • Add a crontab entry such as  
    `*/15 * * * * /usr/bin/python3 /path/to/network_rfm_batch.py`  
    so the script runs every 15 minutes.  
  • The script keeps the timestamp of its latest successful run in
    `last_run.txt`, so every invocation processes **only the new rows.**
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from pyspark.sql import SparkSession, Window
from pyspark.sql import functions as F
from pyspark.sql.types import (
    TimestampType,
    LongType,
    FloatType,
    StringType,
)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration ─ adjust to your environment
# ──────────────────────────────────────────────────────────────────────────────
LOG_GLOB = os.getenv("LOG_DATA_PATH", "./network_logs/*.csv")
OUTPUT_DIR = Path(os.getenv("RFM_OUTPUT_DIR", "./rfm_outputs")).resolve()
LAST_RUN_FILE = Path("./last_run.txt")
RFM_BINS = 5  # number of score buckets (1 … RFM_BINS)

# ensure destination directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_last_run_ts() -> dt.datetime:
    """
    Return the timestamp of the last successful execution (UTC).  
    If the file is missing (first run) we fall back to the Unix epoch.
    """
    if LAST_RUN_FILE.exists():
        return dt.datetime.fromisoformat(LAST_RUN_FILE.read_text().strip())
    return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def persist_run_ts(ts: dt.datetime) -> None:
    """Persist *ts* (UTC) so the next run knows where to resume."""
    LAST_RUN_FILE.write_text(ts.isoformat())


def score_column(rank_col: str, higher_is_better: bool) -> F.Column:
    """
    Map a percentile‑rank column (0–1) to an integer score 1…RFM_BINS.

    • For *F* and *M* a higher rank → better score.  
    • For *R* a lower rank → better score.
    """
    n = float(RFM_BINS)
    if higher_is_better:
        return F.least(F.lit(RFM_BINS), F.ceil(F.col(rank_col) * n).cast("int"))
    # recency: invert the rank
    return F.least(F.lit(RFM_BINS), F.ceil((1.0 - F.col(rank_col)) * n).cast("int"))


# ──────────────────────────────────────────────────────────────────────────────
# Main logic
# ──────────────────────────────────────────────────────────────────────────────
def update_rfm(
    spark: SparkSession,
    log_path_glob: str,
) -> None:
    """Ingest logs newer than *last_run*, recompute RFM scores, save to CSV."""
    last_run = load_last_run_ts()
    print(f"[INFO] Last successful run was at: {last_run.isoformat()}")

    # ── Read raw logs ─────────────────────────────────────────────────────────
    logs_df = (
        spark.read.format("csv")
        .option("header", "true")
        .option("inferSchema", "true")
        .load(log_path_glob)
        # convert/clean timestamp
        .withColumn(
            "ts",
            F.coalesce(
                F.to_timestamp("timestamp"),
                F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"),
                F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss"),
            ),
        )
        .filter(
            # only rows newer than the last run
            F.col("ts") > F.lit(last_run).cast(TimestampType())
        )
        .filter(
            # basic data hygiene
            F.col("src_ip").isNotNull()
            & (F.col("pkt_len").cast(LongType()) >= 0)
            & F.col("ts").isNotNull()
        )
        .select(
            F.col("ts").alias("timestamp"),
            "src_ip",
            F.col("pkt_len").cast(LongType()).alias("pkt_len"),
        )
    )

    if logs_df.rdd.isEmpty():
        print("[INFO] No new rows since last run – nothing to do.")
        return

    logs_df.cache()  # we reuse it in multiple actions

    # ── Derive raw R F M measures per IP ──────────────────────────────────────
    now_utc = dt.datetime.now(dt.timezone.utc)
    now_ts = F.lit(now_utc).cast(TimestampType())

    rfm_raw_df = (
        logs_df.groupBy("src_ip")
        .agg(
            F.max("timestamp").alias("last_seen"),
            F.count("*").alias("frequency_raw"),
            F.sum("pkt_len").alias("monetary_raw"),
        )
        # *recency_raw* is “seconds since last packet”; smaller is better
        .withColumn(
            "recency_raw",
            now_ts.cast("long") - F.col("last_seen").cast("long"),
        )
    )

    # ── Percentile ranks (0…1) ────────────────────────────────────────────────
    win_r = Window.orderBy(F.col("recency_raw").asc())
    win_f = Window.orderBy(F.col("frequency_raw").asc())
    win_m = Window.orderBy(F.col("monetary_raw").asc())

    rfm_ranked_df = (
        rfm_raw_df.withColumn("r_rank", F.percent_rank().over(win_r))
        .withColumn("f_rank", F.percent_rank().over(win_f))
        .withColumn("m_rank", F.percent_rank().over(win_m))
    )

    # ── Discrete 1…RFM_BINS scores ────────────────────────────────────────────
    rfm_scored_df = (
        rfm_ranked_df.withColumn("r_score", score_column("r_rank", False))
        .withColumn("f_score", score_column("f_rank", True))
        .withColumn("m_score", score_column("m_rank", True))
    )

    # Composite score  (optional but convenient: e.g. 543 means R=5, F=4, M=3)
    final_df = (
        rfm_scored_df.withColumn(
            "composite_score",
            (F.col("r_score") * 100 + F.col("f_score") * 10 + F.col("m_score")).cast(
                FloatType()
            ),
        )
        .withColumn("last_updated", F.lit(now_utc.isoformat()).cast(StringType()))
        .select(
            "src_ip",
            "r_score",
            "f_score",
            "m_score",
            "composite_score",
            "last_updated",
        )
        .orderBy("src_ip")
    )

    # ── Persist to CSV ────────────────────────────────────────────────────────
    out_path = OUTPUT_DIR / f"rfm_scores_{now_utc:%Y%m%dT%H%M%SZ}.csv"
    (
        final_df.coalesce(1)  # single CSV file
        .write.mode("overwrite")
        .option("header", "true")
        .csv(str(out_path))
    )
    print(f"[SUCCESS] RFM table written to: {out_path}")

    # remember this successful run
    persist_run_ts(now_utc)


# ──────────────────────────────────────────────────────────────────────────────
# Bootstrap & entry‑point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    spark = (
        SparkSession.builder.appName("Network‑RFM‑Batch")
        .master("local[*]")  # change if submitting to a cluster
        .config("spark.sql.legacy.timeParserPolicy", "LEGACY")
        .getOrCreate()
    )

    try:
        update_rfm(spark, LOG_GLOB)
    finally:
        spark.stop()


# from pyspark.sql import SparkSession, Window
# from pyspark.sql import functions as F
# from pyspark.sql.types import TimestampType, StringType, LongType, StructType, StructField, FloatType
# import datetime
# import math
# import os

# # Import from the updated database_utils
# # These functions now exist and use environment variables via database_utils
# from Database.database_utils import get_jdbc_url, get_jdbc_properties, RFMScore, create_db_and_tables

# # --- Configuration ---
# LOG_DATA_PATH = os.getenv("LOG_DATA_PATH", "./network_logs/*.csv") # Use env var or default
# LOG_DATA_FORMAT = os.getenv("LOG_DATA_FORMAT", "csv")

# # Example Schema (use if CSV header is missing or unreliable)
# # LOG_SCHEMA = StructType([ ... ])
# LOG_SCHEMA = None # Assume header exists by default for simplicity

# RFM_BINS = 5
# # Get table name directly from the SQLAlchemy model in database_utils
# RFM_TABLE_NAME = RFMScore.__tablename__

# # --- Helper Functions ---
# def assign_score_udf(rank_col_name, higher_is_better=True):
#     """Creates a Column expression to map percentile rank to score (1-RFM_BINS)."""
#     num_bins = float(RFM_BINS)
#     if higher_is_better:
#         # Higher rank -> higher score (e.g., F, M)
#         # Using ceil(rank * N) maps ranks (0, 1] to scores [1, N]
#         # Ranks close to 0 get score 1. Rank 1.0 gets score N.
#         return F.least(F.lit(RFM_BINS), F.ceil(F.col(rank_col_name) * num_bins).cast('int'))
#     else:
#         # Lower rank -> higher score (e.g., Recency)
#         # Using ceil((1 - rank) * N) maps ranks [0, 1) to scores [N, 1]
#         # Rank 0.0 gets score N. Ranks close to 1 get score 1.
#         return F.least(F.lit(RFM_BINS), F.ceil((1.0 - F.col(rank_col_name)) * num_bins).cast('int'))

# # --- Main RFM Update Function ---
# def updateRFM(spark: SparkSession, log_path: str, log_format: str, log_schema=None):
#     print(f"Starting RFM update process from logs: {log_path} (format: {log_format})")
#     print(f"Target RFM table: {RFM_TABLE_NAME}")

#     # 1. Read Log Data
#     try:
#         read_options = {"header": "true", "inferSchema": "true"} if log_format == "csv" else {}
#         if log_schema and log_format == "csv":
#              read_options["schema"] = log_schema
#              read_options["inferSchema"] = "false" # Don't infer if schema provided

#         raw_logs_df = spark.read.format(log_format) \
#             .options(**read_options) \
#             .load(log_path)

#         # Basic data cleaning/validation
#         # Ensure required columns exist
#         required_cols = ["timestamp", "src_ip", "pkt_len"]
#         if not all(col in raw_logs_df.columns for col in required_cols):
#             raise ValueError(f"Input data missing required columns. Found: {raw_logs_df.columns}, Required: {required_cols}")

#         # Convert timestamp (handle various potential formats if needed)
#         logs_df = raw_logs_df.withColumn(
#                 "timestamp_parsed",
#                 F.coalesce(
#                     F.to_timestamp(F.col("timestamp"), "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"), # ISO with microseconds
#                     F.to_timestamp(F.col("timestamp"), "yyyy-MM-dd HH:mm:ss"),        # Common format
#                     F.to_timestamp(F.col("timestamp"))                                # Default parser
#                 )
#             )

#         logs_df = logs_df.filter(
#                 F.col("src_ip").isNotNull() &
#                 (F.col("pkt_len").cast(LongType()) >= 0) & # Ensure pkt_len is numeric >= 0
#                 F.col("timestamp_parsed").isNotNull()       # Filter out rows with invalid timestamps
#             ).select(
#                 F.col("timestamp_parsed").alias("timestamp"), # Use the parsed timestamp
#                 "src_ip",
#                 F.col("pkt_len").cast(LongType()).alias("pkt_len")
#             )

#         if logs_df.rdd.isEmpty():
#             print("No valid log data found after cleaning and validation.")
#             return

#         print("Log data loaded and cleaned successfully. Schema:")
#         logs_df.printSchema()
#         print("Sample data:")
#         logs_df.show(5, truncate=False)

#     except Exception as e:
#         print(f"[ERROR] Failed to read or process log data from {log_path}: {e}")
#         import traceback
#         traceback.print_exc()
#         return

#     # 2. Calculate Raw R, F, M values
#     # Use current timestamp from Spark driver for consistency
#     calculation_time = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware UTC
#     calculation_ts = F.lit(calculation_time).cast(TimestampType())
#     print(f"Calculating RFM based on data processed at (UTC): {calculation_time.isoformat()}")

#     rfm_intermediate_df = logs_df.groupBy("src_ip").agg(
#         F.max("timestamp").alias("last_packet_time"),
#         F.count("*").alias("frequency_raw"),
#         F.sum("pkt_len").alias("monetary_raw")
#     ).withColumn(
#         "recency_raw", # Lower value is better (more recent)
#         # Calculate difference in seconds
#         calculation_ts.cast("long") - F.col("last_packet_time").cast("long")
#     )

#     # Handle potential division by zero if frequency is 1 (percent_rank needs >1 distinct values)
#     # Handle potential NaNs or Infs if calculations result in them

#     # 3. Calculate Percentile Ranks
#     window_spec_r = Window.orderBy(F.col("recency_raw").asc()) # Lower recency = lower rank
#     window_spec_f = Window.orderBy(F.col("frequency_raw").asc()) # Lower frequency = lower rank
#     window_spec_m = Window.orderBy(F.col("monetary_raw").asc()) # Lower monetary = lower rank

#     rfm_intermediate_df = rfm_intermediate_df \
#         .withColumn("r_rank", F.percent_rank().over(window_spec_r)) \
#         .withColumn("f_rank", F.percent_rank().over(window_spec_f)) \
#         .withColumn("m_rank", F.percent_rank().over(window_spec_m))

#     print("Intermediate RFM calculations with ranks:")
#     rfm_intermediate_df.show(10, truncate=False)

#     # 4. Assign Scores (1 to RFM_BINS) based on Ranks
#     final_rfm_df = rfm_intermediate_df.withColumn(
#         "r_score", assign_score_udf("r_rank", higher_is_better=False) # Lower recency rank -> Higher score
#     ).withColumn(
#         "f_score", assign_score_udf("f_rank", higher_is_better=True) # Higher frequency rank -> Higher score
#     ).withColumn(
#         "m_score", assign_score_udf("m_rank", higher_is_better=True) # Higher monetary rank -> Higher score
#     )

#     # Calculate composite score
#     final_rfm_df = final_rfm_df.withColumn(
#         "composite_score",
#         (F.col("r_score") * 100 + F.col("f_score") * 10 + F.col("m_score")).cast(FloatType())
#     ).withColumn(
#         # Use the consistent calculation time, formatted as ISO string for DB
#         "last_updated", F.lit(calculation_time.isoformat())
#     )

#     # Select and cast final columns to match the database schema (RFMScore model)
#     output_df = final_rfm_df.select(
#         F.col("src_ip").alias("src_ip"), # Ensure column name matches PK
#         F.col("r_score").cast(FloatType()),
#         F.col("f_score").cast(FloatType()),
#         F.col("m_score").cast(FloatType()),
#         F.col("composite_score").cast(FloatType()),
#         F.col("last_updated").cast(StringType()) # Matches String type in RFMScore model
#     )

#     print("Final RFM scores calculated:")
#     output_df.show(10, truncate=False)
#     output_df.printSchema() # Verify schema before writing

#     # 5. Store RFM Scores in Database
#     print(f"Attempting to write RFM scores to database table: {RFM_TABLE_NAME}")
#     try:
#         jdbc_url = get_jdbc_url() # Get URL from database_utils
#         jdbc_properties = get_jdbc_properties() # Get properties from database_utils

#         # Using "overwrite" is simple but replaces all existing scores.
#         # For incremental updates, you'd typically:
#         # 1. Write new scores to a temporary table.
#         # 2. Use SQL MERGE (or INSERT ON CONFLICT UPDATE) to update the main table.
#         # This requires executing SQL via JDBC/psycopg2 after the Spark write.
#         output_df.write \
#             .format("jdbc") \
#             .option("url", jdbc_url) \
#             .option("dbtable", RFM_TABLE_NAME) \
#             .option("user", jdbc_properties.get("user")) \
#             .option("password", jdbc_properties.get("password")) \
#             .option("driver", jdbc_properties.get("driver")) \
#             .mode("overwrite") \
#             .save()

#         print(f"Successfully wrote {output_df.count()} RFM records to the database.")

#     except Exception as e:
#         print(f"[ERROR] Failed to write RFM scores to database: {e}")
#         import traceback
#         traceback.print_exc()
#         # Consider logging the error more formally or raising it


# if __name__ == "__main__":
#     print("--- Pyspark RFM Batch Processor ---")

#     # --- Create Dummy Log Data if necessary ---
#     log_dir = "./network_logs"
#     if not os.path.exists(log_dir):
#         print(f"Log directory '{log_dir}' not found, creating it.")
#         os.makedirs(log_dir)
#     if not any(fname.endswith('.csv') for fname in os.listdir(log_dir)):
#          print(f"No CSV files found in '{log_dir}'. Creating dummy log file...")
#          dummy_file_path = os.path.join(log_dir, "dummy_log.csv")
#          with open(dummy_file_path, "w") as f:
#              f.write("timestamp,src_ip,pkt_len\n")
#              now = datetime.datetime.now(datetime.timezone.utc)
#              f.write(f"{now.isoformat()},192.168.1.10,100\n")
#              f.write(f"{(now - datetime.timedelta(seconds=10)).isoformat()},192.168.1.11,500\n")
#              f.write(f"{(now - datetime.timedelta(minutes=5)).isoformat()},192.168.1.10,120\n")
#              f.write(f"{(now - datetime.timedelta(hours=1)).isoformat()},10.0.0.5,1480\n")
#              f.write(f"{(now - datetime.timedelta(days=1)).isoformat()},192.168.1.10,80\n")
#              f.write(f"{(now - datetime.timedelta(days=2)).isoformat()},10.0.0.5,1400\n")
#              f.write(f"invalid-timestamp,10.0.0.6,100\n") # Test invalid timestamp filter
#              f.write(f"{now.isoformat()},,200\n") # Test null IP filter
#          print(f"Dummy log file created at: {dummy_file_path}")
#     else:
#         print(f"Using existing log files found in: {log_dir}")


#     # --- Ensure Database Table Exists ---
#     # This should be called *before* initializing Spark if Spark might connect early,
#     # but it's generally safe here before the main processing logic.
#     # It uses the SQLAlchemy engine configured in database_utils.
#     print("Ensuring database and table exist...")
#     create_db_and_tables() # Call the function from database_utils

#     # --- Initialize Spark Session ---
#     print("Initializing Spark Session...")
#     try:
#         spark = SparkSession.builder \
#             .appName("RFMBatchProcessor") \
#             .master("local[*]") \
#             .config("spark.jars.packages", "org.postgresql:postgresql:42.7.3") \
#             .config("spark.sql.legacy.timeParserPolicy", "LEGACY") \
#             .config("spark.sql.adaptive.enabled", "true") \
#             .config("spark.driver.memory", "1g") \
#             .getOrCreate()

#         print("Spark Session initialized successfully.")

#         # --- Execute RFM Update ---
#         updateRFM(spark, LOG_DATA_PATH, LOG_DATA_FORMAT, log_schema=LOG_SCHEMA)

#         # --- Stop Spark Session ---
#         print("Stopping Spark Session...")
#         spark.stop()

#     except Exception as e:
#          print(f"[ERROR] An error occurred during Spark initialization or execution: {e}")
#          import traceback
#          traceback.print_exc()

#     print("\n--- RFM Batch Processing Finished ---")
