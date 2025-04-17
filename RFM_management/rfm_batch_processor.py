
from pyspark.sql import SparkSession, Window
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType, StringType, LongType, StructType, StructField, FloatType # Added FloatType
import datetime
import math
import os # For checking directories

# Import from the updated database_utils
# These functions now exist and use environment variables via database_utils
from database_utils import get_jdbc_url, get_jdbc_properties, RFMScore, create_db_and_tables

# --- Configuration ---
LOG_DATA_PATH = os.getenv("LOG_DATA_PATH", "./network_logs/*.csv") # Use env var or default
LOG_DATA_FORMAT = os.getenv("LOG_DATA_FORMAT", "csv")

# Example Schema (use if CSV header is missing or unreliable)
# LOG_SCHEMA = StructType([ ... ])
LOG_SCHEMA = None # Assume header exists by default for simplicity

RFM_BINS = 5
# Get table name directly from the SQLAlchemy model in database_utils
RFM_TABLE_NAME = RFMScore.__tablename__

# --- Helper Functions ---
def assign_score_udf(rank_col_name, higher_is_better=True):
    """Creates a Column expression to map percentile rank to score (1-RFM_BINS)."""
    num_bins = float(RFM_BINS)
    if higher_is_better:
        # Higher rank -> higher score (e.g., F, M)
        # Using ceil(rank * N) maps ranks (0, 1] to scores [1, N]
        # Ranks close to 0 get score 1. Rank 1.0 gets score N.
        return F.least(F.lit(RFM_BINS), F.ceil(F.col(rank_col_name) * num_bins).cast('int'))
    else:
        # Lower rank -> higher score (e.g., Recency)
        # Using ceil((1 - rank) * N) maps ranks [0, 1) to scores [N, 1]
        # Rank 0.0 gets score N. Ranks close to 1 get score 1.
        return F.least(F.lit(RFM_BINS), F.ceil((1.0 - F.col(rank_col_name)) * num_bins).cast('int'))

# --- Main RFM Update Function ---
def updateRFM(spark: SparkSession, log_path: str, log_format: str, log_schema=None):
    print(f"Starting RFM update process from logs: {log_path} (format: {log_format})")
    print(f"Target RFM table: {RFM_TABLE_NAME}")

    # 1. Read Log Data
    try:
        read_options = {"header": "true", "inferSchema": "true"} if log_format == "csv" else {}
        if log_schema and log_format == "csv":
             read_options["schema"] = log_schema
             read_options["inferSchema"] = "false" # Don't infer if schema provided

        raw_logs_df = spark.read.format(log_format) \
            .options(**read_options) \
            .load(log_path)

        # Basic data cleaning/validation
        # Ensure required columns exist
        required_cols = ["timestamp", "src_ip", "pkt_len"]
        if not all(col in raw_logs_df.columns for col in required_cols):
            raise ValueError(f"Input data missing required columns. Found: {raw_logs_df.columns}, Required: {required_cols}")

        # Convert timestamp (handle various potential formats if needed)
        logs_df = raw_logs_df.withColumn(
                "timestamp_parsed",
                F.coalesce(
                    F.to_timestamp(F.col("timestamp"), "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"), # ISO with microseconds
                    F.to_timestamp(F.col("timestamp"), "yyyy-MM-dd HH:mm:ss"),        # Common format
                    F.to_timestamp(F.col("timestamp"))                                # Default parser
                )
            )

        logs_df = logs_df.filter(
                F.col("src_ip").isNotNull() &
                (F.col("pkt_len").cast(LongType()) >= 0) & # Ensure pkt_len is numeric >= 0
                F.col("timestamp_parsed").isNotNull()       # Filter out rows with invalid timestamps
            ).select(
                F.col("timestamp_parsed").alias("timestamp"), # Use the parsed timestamp
                "src_ip",
                F.col("pkt_len").cast(LongType()).alias("pkt_len")
            )

        if logs_df.rdd.isEmpty():
            print("No valid log data found after cleaning and validation.")
            return

        print("Log data loaded and cleaned successfully. Schema:")
        logs_df.printSchema()
        print("Sample data:")
        logs_df.show(5, truncate=False)

    except Exception as e:
        print(f"[ERROR] Failed to read or process log data from {log_path}: {e}")
        import traceback
        traceback.print_exc()
        return

    # 2. Calculate Raw R, F, M values
    # Use current timestamp from Spark driver for consistency
    calculation_time = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware UTC
    calculation_ts = F.lit(calculation_time).cast(TimestampType())
    print(f"Calculating RFM based on data processed at (UTC): {calculation_time.isoformat()}")

    rfm_intermediate_df = logs_df.groupBy("src_ip").agg(
        F.max("timestamp").alias("last_packet_time"),
        F.count("*").alias("frequency_raw"),
        F.sum("pkt_len").alias("monetary_raw")
    ).withColumn(
        "recency_raw", # Lower value is better (more recent)
        # Calculate difference in seconds
        calculation_ts.cast("long") - F.col("last_packet_time").cast("long")
    )

    # Handle potential division by zero if frequency is 1 (percent_rank needs >1 distinct values)
    # Handle potential NaNs or Infs if calculations result in them

    # 3. Calculate Percentile Ranks
    window_spec_r = Window.orderBy(F.col("recency_raw").asc()) # Lower recency = lower rank
    window_spec_f = Window.orderBy(F.col("frequency_raw").asc()) # Lower frequency = lower rank
    window_spec_m = Window.orderBy(F.col("monetary_raw").asc()) # Lower monetary = lower rank

    rfm_intermediate_df = rfm_intermediate_df \
        .withColumn("r_rank", F.percent_rank().over(window_spec_r)) \
        .withColumn("f_rank", F.percent_rank().over(window_spec_f)) \
        .withColumn("m_rank", F.percent_rank().over(window_spec_m))

    print("Intermediate RFM calculations with ranks:")
    rfm_intermediate_df.show(10, truncate=False)

    # 4. Assign Scores (1 to RFM_BINS) based on Ranks
    final_rfm_df = rfm_intermediate_df.withColumn(
        "r_score", assign_score_udf("r_rank", higher_is_better=False) # Lower recency rank -> Higher score
    ).withColumn(
        "f_score", assign_score_udf("f_rank", higher_is_better=True) # Higher frequency rank -> Higher score
    ).withColumn(
        "m_score", assign_score_udf("m_rank", higher_is_better=True) # Higher monetary rank -> Higher score
    )

    # Calculate composite score
    final_rfm_df = final_rfm_df.withColumn(
        "composite_score",
        (F.col("r_score") * 100 + F.col("f_score") * 10 + F.col("m_score")).cast(FloatType())
    ).withColumn(
        # Use the consistent calculation time, formatted as ISO string for DB
        "last_updated", F.lit(calculation_time.isoformat())
    )

    # Select and cast final columns to match the database schema (RFMScore model)
    output_df = final_rfm_df.select(
        F.col("src_ip").alias("src_ip"), # Ensure column name matches PK
        F.col("r_score").cast(FloatType()),
        F.col("f_score").cast(FloatType()),
        F.col("m_score").cast(FloatType()),
        F.col("composite_score").cast(FloatType()),
        F.col("last_updated").cast(StringType()) # Matches String type in RFMScore model
    )

    print("Final RFM scores calculated:")
    output_df.show(10, truncate=False)
    output_df.printSchema() # Verify schema before writing

    # 5. Store RFM Scores in Database
    print(f"Attempting to write RFM scores to database table: {RFM_TABLE_NAME}")
    try:
        jdbc_url = get_jdbc_url() # Get URL from database_utils
        jdbc_properties = get_jdbc_properties() # Get properties from database_utils

        # Using "overwrite" is simple but replaces all existing scores.
        # For incremental updates, you'd typically:
        # 1. Write new scores to a temporary table.
        # 2. Use SQL MERGE (or INSERT ON CONFLICT UPDATE) to update the main table.
        # This requires executing SQL via JDBC/psycopg2 after the Spark write.
        output_df.write \
            .format("jdbc") \
            .option("url", jdbc_url) \
            .option("dbtable", RFM_TABLE_NAME) \
            .option("user", jdbc_properties.get("user")) \
            .option("password", jdbc_properties.get("password")) \
            .option("driver", jdbc_properties.get("driver")) \
            .mode("overwrite") \
            .save()

        print(f"Successfully wrote {output_df.count()} RFM records to the database.")

    except Exception as e:
        print(f"[ERROR] Failed to write RFM scores to database: {e}")
        import traceback
        traceback.print_exc()
        # Consider logging the error more formally or raising it


if __name__ == "__main__":
    print("--- Pyspark RFM Batch Processor ---")

    # --- Create Dummy Log Data if necessary ---
    log_dir = "./network_logs"
    if not os.path.exists(log_dir):
        print(f"Log directory '{log_dir}' not found, creating it.")
        os.makedirs(log_dir)
    if not any(fname.endswith('.csv') for fname in os.listdir(log_dir)):
         print(f"No CSV files found in '{log_dir}'. Creating dummy log file...")
         dummy_file_path = os.path.join(log_dir, "dummy_log.csv")
         with open(dummy_file_path, "w") as f:
             f.write("timestamp,src_ip,pkt_len\n")
             now = datetime.datetime.now(datetime.timezone.utc)
             f.write(f"{now.isoformat()},192.168.1.10,100\n")
             f.write(f"{(now - datetime.timedelta(seconds=10)).isoformat()},192.168.1.11,500\n")
             f.write(f"{(now - datetime.timedelta(minutes=5)).isoformat()},192.168.1.10,120\n")
             f.write(f"{(now - datetime.timedelta(hours=1)).isoformat()},10.0.0.5,1480\n")
             f.write(f"{(now - datetime.timedelta(days=1)).isoformat()},192.168.1.10,80\n")
             f.write(f"{(now - datetime.timedelta(days=2)).isoformat()},10.0.0.5,1400\n")
             f.write(f"invalid-timestamp,10.0.0.6,100\n") # Test invalid timestamp filter
             f.write(f"{now.isoformat()},,200\n") # Test null IP filter
         print(f"Dummy log file created at: {dummy_file_path}")
    else:
        print(f"Using existing log files found in: {log_dir}")


    # --- Ensure Database Table Exists ---
    # This should be called *before* initializing Spark if Spark might connect early,
    # but it's generally safe here before the main processing logic.
    # It uses the SQLAlchemy engine configured in database_utils.
    print("Ensuring database and table exist...")
    create_db_and_tables() # Call the function from database_utils

    # --- Initialize Spark Session ---
    print("Initializing Spark Session...")
    try:
        spark = SparkSession.builder \
            .appName("RFMBatchProcessor") \
            .master("local[*]") \
            .config("spark.jars.packages", "org.postgresql:postgresql:42.7.3") \
            .config("spark.sql.legacy.timeParserPolicy", "LEGACY") \
            .config("spark.sql.adaptive.enabled", "true") # Optional: Adaptive Query Execution
            .config("spark.driver.memory", "1g") # Adjust memory as needed
            .getOrCreate()

        print("Spark Session initialized successfully.")

        # --- Execute RFM Update ---
        updateRFM(spark, LOG_DATA_PATH, LOG_DATA_FORMAT, log_schema=LOG_SCHEMA)

        # --- Stop Spark Session ---
        print("Stopping Spark Session...")
        spark.stop()

    except Exception as e:
         print(f"[ERROR] An error occurred during Spark initialization or execution: {e}")
         import traceback
         traceback.print_exc()

    print("\n--- RFM Batch Processing Finished ---")
