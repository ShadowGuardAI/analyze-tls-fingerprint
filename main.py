import argparse
import logging
import pandas as pd
import hashlib
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dummy JA3/JA3S database (replace with a real one)
JA3_DATABASE = {
    "839cca7d4f505a770746e8a593448bb6": {"application": "curl", "description": "Standard curl client"},
    "771c2b011b35a8373f5202ca27659bb0": {"application": "OpenSSL", "description": "Generic OpenSSL client"},
    "d4e185393f7d6875a4795151712043bb": {"application": "Chrome", "description": "Chrome browser (desktop)"},
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyzes TLS fingerprints (JA3/JA3S).")
    parser.add_argument("fingerprint", help="The JA3 or JA3S fingerprint to analyze.")
    parser.add_argument("-d", "--database", help="Path to the JA3/JA3S database file (CSV).  Defaults to internal dummy db.", required=False) # Optional database path
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-o", "--output", help="Output file to save the analysis results (CSV format).", required=False)

    return parser


def load_database(db_path=None):
    """
    Loads the JA3/JA3S database from a CSV file.

    Args:
        db_path (str, optional): The path to the CSV database file. Defaults to None,
            in which case a hardcoded dummy database is used.

    Returns:
        dict: A dictionary representing the JA3/JA3S database, where keys are fingerprints
            and values are dictionaries containing application and description information.
    """
    if db_path:
        try:
            df = pd.read_csv(db_path)
            # Assuming the CSV has columns 'fingerprint', 'application', and 'description'
            db = {row['fingerprint']: {'application': row['application'], 'description': row['description']}
                for index, row in df.iterrows()}
            logging.info(f"Loaded JA3/JA3S database from {db_path}")
            return db
        except FileNotFoundError:
            logging.error(f"Database file not found: {db_path}")
            print(f"Error: Database file not found: {db_path}")
            sys.exit(1)
        except pd.errors.EmptyDataError:
            logging.error(f"Database file is empty: {db_path}")
            print(f"Error: Database file is empty: {db_path}")
            sys.exit(1)
        except KeyError as e:
            logging.error(f"Database file missing required column: {e}")
            print(f"Error: Database file missing required column: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading database file: {e}")
            print(f"Error loading database file: {e}")
            sys.exit(1)


    else:
        logging.info("Using internal dummy JA3/JA3S database.")
        return JA3_DATABASE


def analyze_fingerprint(fingerprint, database):
    """
    Analyzes a given JA3/JA3S fingerprint against the provided database.

    Args:
        fingerprint (str): The JA3 or JA3S fingerprint to analyze.
        database (dict): The JA3/JA3S database (dictionary).

    Returns:
        dict: A dictionary containing the analysis results.  Returns None if not found.
    """
    # Input validation: check if fingerprint is a valid MD5 hash
    try:
        if len(fingerprint) != 32:
            raise ValueError("Invalid fingerprint length.  Must be 32 characters (MD5 hash).")
        int(fingerprint, 16)  # Check if it's a valid hexadecimal string
    except ValueError as e:
        logging.error(f"Invalid fingerprint format: {e}")
        print(f"Error: Invalid fingerprint format: {e}")
        return None

    # Perform the analysis
    if fingerprint in database:
        analysis_result = database[fingerprint]
        logging.info(f"Fingerprint {fingerprint} found in database. Application: {analysis_result['application']}")
        return analysis_result
    else:
        logging.info(f"Fingerprint {fingerprint} not found in database.")
        return None



def save_results_to_csv(results, output_file):
    """
    Saves the analysis results to a CSV file.

    Args:
        results (dict): The analysis results to save.
        output_file (str): The path to the output CSV file.
    """
    try:
        df = pd.DataFrame([results])  # Convert dictionary to DataFrame
        df.to_csv(output_file, index=False)
        logging.info(f"Analysis results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to CSV: {e}")
        print(f"Error: Error saving results to CSV: {e}")

def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    database = load_database(args.database)

    # Analyze the fingerprint
    analysis_result = analyze_fingerprint(args.fingerprint, database)

    if analysis_result:
        print(f"Fingerprint: {args.fingerprint}")
        print(f"  Application: {analysis_result['application']}")
        print(f"  Description: {analysis_result['description']}")

        if args.output:
            # Prepare data for CSV output.  Ensure all fields are present.
            output_data = {
                'fingerprint': args.fingerprint,
                'application': analysis_result['application'],
                'description': analysis_result['description']
            }
            save_results_to_csv(output_data, args.output)
    else:
        print(f"Fingerprint {args.fingerprint} not found in database.")


if __name__ == "__main__":
    main()