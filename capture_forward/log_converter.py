import time
import os
import csv
import logging
import sys
import datetime
from pathlib import Path

# --- Configuration ---
# Input log file from C program
CAPTURE_LOG_FILE = "./capture_log.tsv"
# Output directory for CSV files (must match PySpark input)
OUTPUT_CSV_DIR = "./network_logs"
# How often to check for new lines (seconds)
POLL_INTERVAL = 0.5
# How often to rotate the output CSV file (seconds). Set to None or 0 to disable rotation.
CSV_ROTATION_INTERVAL = 3600 # Rotate every hour
# Expected columns in the TSV file (from C program)
INPUT_COLUMNS = ["Timestamp", "SrcIP", "DstIP", "Proto", "SrcPort", "DstPort", "Length", "Flags"]
# Columns to select and write to CSV (match PySpark expected input)
OUTPUT_COLUMNS = ["timestamp", "src_ip", "pkt_len"]
# --- End Configuration ---

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Global state for file handling ---
current_csv_file = None
current_csv_writer = None
current_csv_path = None
last_rotation_time = time.time()
# ---

def get_output_csv_path():
    """Generates the path for the current output CSV file."""
    now = datetime.datetime.now()
    filename = f"netlog_{now.strftime('%Y%m%d_%H%M%S')}.csv"
    return Path(OUTPUT_CSV_DIR) / filename

def open_new_csv_file():
    """Opens a new CSV file for writing and returns the file object and writer."""
    global current_csv_file, current_csv_writer, current_csv_path, last_rotation_time

    # Ensure output directory exists
    Path(OUTPUT_CSV_DIR).mkdir(parents=True, exist_ok=True)

    # Close previous file if open
    if current_csv_file and not current_csv_file.closed:
        current_csv_file.close()
        logging.info(f"Closed previous CSV file: {current_csv_path}")

    new_path = get_output_csv_path()
    logging.info(f"Opening new CSV file for writing: {new_path}")
    try:
        # Use newline='' to prevent extra blank rows in CSV
        file_obj = open(new_path, 'w', newline='', encoding='utf-8')
        writer = csv.writer(file_obj)
        # Write header row
        writer.writerow(OUTPUT_COLUMNS)
        current_csv_file = file_obj
        current_csv_writer = writer
        current_csv_path = new_path
        last_rotation_time = time.time()
        return file_obj, writer
    except IOError as e:
        logging.error(f"Failed to open or write header to {new_path}: {e}")
        return None, None

def parse_and_write_log_line(line):
    """Parses TSV, extracts relevant fields, and writes to the current CSV file."""
    global current_csv_writer, current_csv_file

    line = line.strip()
    if not line or line.startswith('#') or line.startswith('Timestamp'):
        return # Skip empty, comments, header

    parts = line.split('\t')
    if len(parts) != len(INPUT_COLUMNS):
        logging.warning(f"Skipping malformed line (expected {len(INPUT_COLUMNS)} cols, got {len(parts)}): {line}")
        return

    try:
        # Create dict from input line using INPUT_COLUMNS
        input_data = dict(zip(INPUT_COLUMNS, parts))

        # Prepare output row based on OUTPUT_COLUMNS
        output_row = [
            input_data.get("Timestamp"), # -> timestamp
            input_data.get("SrcIP"),     # -> src_ip
            input_data.get("Length")     # -> pkt_len (assuming Length is packet length)
        ]

        # Basic validation (optional, but recommended)
        if not all(output_row): # Check for None or empty strings if extraction failed
             logging.warning(f"Skipping line with missing required data: {line}")
             return
        # Could add more specific validation (is Length numeric?)

        # Ensure CSV writer is available (handles rotation)
        if current_csv_writer is None or (CSV_ROTATION_INTERVAL and time.time() - last_rotation_time > CSV_ROTATION_INTERVAL):
             _, writer = open_new_csv_file()
             if not writer:
                 logging.error("Cannot write log - CSV writer not available.")
                 return # Skip writing if file couldn't be opened
             current_csv_writer = writer


        # Write the selected data to the CSV file
        current_csv_writer.writerow(output_row)
        # Flushing ensures data is written sooner, but impacts performance.
        # Useful if you want the PySpark job to pick up recent data quickly after rotation.
        # current_csv_file.flush()

    except (ValueError, IndexError, KeyError) as e:
        logging.warning(f"Skipping line due to parsing/extraction error ({e}): {line}")
    except Exception as e:
        logging.error(f"Unexpected error writing line '{line}': {e}", exc_info=True)


def tail_capture_log():
    """Tails the capture log file and processes new lines."""
    logging.info(f"Starting log converter.")
    logging.info(f"Monitoring TSV log: {CAPTURE_LOG_FILE}")
    logging.info(f"Writing CSV logs to: {OUTPUT_CSV_DIR}")

    input_fd = None
    current_inode = None

    while True:
        try:
            if not os.path.exists(CAPTURE_LOG_FILE):
                logging.warning(f"Input log file '{CAPTURE_LOG_FILE}' not found. Waiting...")
                if input_fd: input_fd.close(); input_fd = None; current_inode = None
                time.sleep(POLL_INTERVAL * 10)
                continue

            stat_result = os.stat(CAPTURE_LOG_FILE)
            inode = stat_result.st_ino

            if input_fd is None or inode != current_inode:
                if input_fd:
                    logging.info("Input TSV file inode changed. Reopening.")
                    input_fd.close()
                try:
                    input_fd = open(CAPTURE_LOG_FILE, 'r')
                    logging.info(f"Opened input TSV file: {CAPTURE_LOG_FILE}")
                    input_fd.seek(0, os.SEEK_END) # Go to end for new lines
                    current_inode = inode
                    logging.info("Seeked to end of input file.")
                except Exception as e:
                    logging.error(f"Error opening input file {CAPTURE_LOG_FILE}: {e}")
                    if input_fd: input_fd.close()
                    input_fd = None; current_inode = None
                    time.sleep(POLL_INTERVAL * 5)
                    continue

            # Read new lines from TSV
            line = input_fd.readline()
            while line:
                parse_and_write_log_line(line)
                line = input_fd.readline()

            # Check for CSV rotation based on time
            if CSV_ROTATION_INTERVAL and time.time() - last_rotation_time > CSV_ROTATION_INTERVAL:
                 logging.info("CSV rotation interval reached.")
                 open_new_csv_file() # This will close the old and open a new one

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            logging.info("Stopping log converter.")
            if input_fd: input_fd.close()
            if current_csv_file and not current_csv_file.closed: current_csv_file.close()
            sys.exit(0)
        except Exception as e:
            logging.error(f"An unexpected error occurred in tail loop: {e}", exc_info=True)
            if input_fd: input_fd.close(); input_fd = None; current_inode = None
            if current_csv_file and not current_csv_file.closed: current_csv_file.close()
            current_csv_file = None; current_csv_writer = None; current_csv_path = None # Reset CSV state
            time.sleep(POLL_INTERVAL * 5) # Wait longer after error

if __name__ == "__main__":
    open_new_csv_file() # Open the initial CSV file
    tail_capture_log()
