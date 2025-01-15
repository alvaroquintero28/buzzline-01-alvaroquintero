"""
basic_consumer_alvaro.py

Read a log file as it is being written. 
"""

#####################################
# Import Modules
#####################################

# Import packages from Python Standard Library
import os
import time
import logging
import threading

from utils.utils_logger import logger, get_log_file_path


def process_message(log_file, alert_message, alert_level):
    """
    Reads a log file and processes messages, handling potential errors.

    Args:
        log_file: Path to the log file.
        alert_message: The message to watch for.
        alert_level: The logging level for alerts (e.g., logging.WARNING).
    """

    try:
        with open(log_file, "r") as file:
            file.seek(0, os.SEEK_END)

            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue

                message = line.strip()
                print(f"Consumed log message: {message}")
                
                if alert_message in message:
                    print(f"ALERT: {alert_level.upper()} - {message}")
                    logging.log(alert_level, f"ALERT: {alert_level.upper()} - {message}")
                    # Optionally, you can take further action based on the alert
                    # ... e.g., send a notification, trigger another process
    except FileNotFoundError:
        logger.error(f"Log file '{log_file}' not found.")
        return
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        return

def monitor_log(log_file, alert_messages, alert_levels):
    """
    Monitors the log file and process different alert scenarios based on messages
    Using threading.Thread for concurrent monitoring
    """
    threads = []

    for message, level in alert_messages.items():
        thread = threading.Thread(target=process_message,
                                 args=(log_file, message, level))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to finish

# Define main function for this script.
def main():
    logger.info("START...")

    log_file_path = get_log_file_path()
    logger.info(f"Reading file located at: {log_file_path}.")

    try:
        ALERT_MESSAGES = {
            "I just watched a football game! It was a nail-biter.": logging.WARNING,
            "System overloaded!": logging.ERROR,
             "Network connection lost": logging.CRITICAL
        }

        monitor_log(log_file_path,ALERT_MESSAGES,None)  # Pass the dictionary to monitor_log


    except KeyboardInterrupt:
        print("User stopped the process.")
        logger.info("END.....")
    except Exception as e:
        logging.exception(f"An unexpected error occurred in main(): {e}")
        logger.error("END.....")
        
        
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main()
