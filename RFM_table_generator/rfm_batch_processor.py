#!/usr/bin/env python3
"""
rfm_job.py

Periodically recompute RFM (Recency, Frequency, Monetary) metrics for each IP address using CSV log files.

Environment variables (all are optional):
    NETWORK_LOG_DIR   Directory containing network-log CSV files.               [default: "network_logs"]
    OUTPUT_FILE       Path for the generated RFM CSV file.                      [default: "rfm_scores.csv"]
    INTERVAL_SECONDS  Seconds to wait between successive recomputations.        [default: 3600]
    TIMESTAMP_COLUMN  Column that contains the timestamp.                       [default: "timestamp"]
    IP_COLUMN         Column that contains the IP address.                      [default: "ip_address"]
    MONETARY_COLUMN   Column used for the monetary metric (e.g., bytes_sent).   [default: "bytes_sent"]
    DATE_FORMAT       Optional strptime pattern if timestamps are not ISO‑8601.

The script starts an infinite loop inside the container. At each cycle it:
  • Scans NETWORK_LOG_DIR for all *.csv files.
  • Loads and concatenates them with pandas.
  • Converts TIMESTAMP_COLUMN to pandas datetime (using DATE_FORMAT if given).
  • Calculates per‑IP metrics:
        Recency  = (now – last activity) in *days*.
        Frequency = number of rows (events).
        Monetary  = sum of MONETARY_COLUMN (if present).
  • Writes the resulting table to OUTPUT_FILE.
  • Sleeps INTERVAL_SECONDS, then repeats.

Typical Dockerfile snippet:
    FROM python:3.12-slim
    WORKDIR /app
    COPY rfm_job.py .
    RUN pip install --no-cache-dir pandas
    ENV NETWORK_LOG_DIR=/app/network_logs INTERVAL_SECONDS=1800
    CMD ["python", "rfm_job.py"]

Mount or COPY your network_logs/ folder into /app/network_logs (or override via NETWORK_LOG_DIR).
"""

import os
import time
import glob
import logging
from datetime import datetime, timezone
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def compute_rfm(df: pd.DataFrame, now: pd.Timestamp, ts_col: str, ip_col: str, mon_col: str) -> pd.DataFrame:
    """Return a DataFrame with R, F, (optional) M for each IP."""

    # Recency (days since last event per IP)
    recency = (now - df.groupby(ip_col)[ts_col].max()).dt.total_seconds() / 86_400
    recency = recency.rename("recency_days")

    # Frequency (number of events)
    frequency = df.groupby(ip_col)[ts_col].count().rename("frequency")

    if mon_col in df.columns:
        monetary = df.groupby(ip_col)[mon_col].sum().rename("monetary")
        rfm = pd.concat([recency, frequency, monetary], axis=1)
    else:
        logging.warning("Monetary column '%s' not found — returning R & F only.", mon_col)
        rfm = pd.concat([recency, frequency], axis=1)

    return rfm.reset_index()


def load_logs(directory: str, ts_col: str, date_format: str | None) -> pd.DataFrame:
    """Read and concatenate every CSV in *directory* into a single DataFrame."""

    # files = glob.glob(os.path.join(directory, "*.csv"))
    files = os.listdir(directory)
    if not files:
        logging.warning("No CSV files found in %s", directory)
        return pd.DataFrame()

    dfs = []
    for path in files:
        try:
            tmp = pd.read_csv(os.path.join(directory, path))
            logging.info(tmp)                                        
            dfs.append(tmp)
        except Exception as exc:
            logging.error("%s — could not read (%s)", path, exc)

    # if not dfs:
    #     return pd.DataFrame()
    if len(dfs) == 1:
        df = dfs[0]
    else:
        df = pd.concat(dfs, ignore_index=True)

    # Parse timestamp column
    if ts_col not in df.columns:
        raise KeyError(f"Timestamp column '{ts_col}' not present in data.")

    if date_format:
        df[ts_col] = pd.to_datetime(df[ts_col], format=date_format, errors="coerce")
    else:
        df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")

     # Normalise to UTC and then strip tz to get naive UTC
    # if df[ts_col].dt.tz is None:
    #     # tz-naive already — assume it's UTC
    #     pass
    # else:
        # df[ts_col] = (
        #     df[ts_col]
        #     .dt.tz_convert("UTC")   # convert any timezone → UTC
        #     .dt.tz_localize(None)    # drop timezone to make tz‑naive
        # )

    # df = df.dropna(subset=[ts_col])
    return df


def main() -> None:
    # Read configuration from environment
    log_dir = os.getenv("NETWORK_LOG_DIR", "network_logs")
    output_file = os.getenv("OUTPUT_FILE", "rfm_scores.csv")
    interval = int(os.getenv("INTERVAL_SECONDS", "3600"))
    ts_col = os.getenv("TIMESTAMP_COLUMN", "timestamp")
    ip_col = os.getenv("IP_COLUMN", "client_ip")
    mon_col = os.getenv("MONETARY_COLUMN", "http_body_length")
    date_format = os.getenv("DATE_FORMAT")

    logging.info(
        "Running RFM refresher every %s seconds | source: %s | output: %s",
        interval,
        log_dir,
        output_file,
    )

    while True:
        try:
            df = load_logs(log_dir, ts_col, date_format)
            if df.empty:
                logging.info("Skip — no data available.")
            else:
                now = pd.Timestamp.now()
                rfm_df = compute_rfm(df, now, ts_col, ip_col, mon_col)
                rfm_df.to_csv(output_file, index=False)
                logging.info("RFM table saved (%d rows)", len(rfm_df))
        except Exception as exc:
            logging.exception("RFM computation failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
