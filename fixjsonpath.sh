#!/bin/bash

# A script to correct the absolute file paths within the cert_database.json file.
# It strips the old, incorrect base directory path, making the paths relative.
# This script creates a date-stamped backup before making any changes.

# --- Configuration ---
# IMPORTANT: Set this to the incorrect base path found in your error messages.
# The trailing slash is important!
OLD_BASE_PATH="/home/youruser/old-ca-path/"

# --- Script Variables ---
CA_BASE_DIR="$(pwd)"
DB_DIR="${CA_BASE_DIR}/db"
JSON_FILE="${DB_DIR}/cert_database.json"

# Generate a timestamp for the backup file, e.g., "10-21-25"
TIMESTAMP=$(date +%m-%d-%y)
BACKUP_FILE="${DB_DIR}/${TIMESTAMP}.cert_database.json.bak"

# --- Safety Check ---
if [ ! -f "$JSON_FILE" ]; then
    echo "ERROR: Cannot find the JSON database at ${JSON_FILE}"
    echo "Please run this script from your main CA directory (the one containing 'db', 'certs', etc.)."
    exit 1
fi

# --- Backup ---
echo "Backing up your existing JSON database to ${BACKUP_FILE}..."
cp "$JSON_FILE" "$BACKUP_FILE"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create a backup. Aborting."
    exit 1
fi
echo "Backup successful."

# --- Path Correction ---
echo "Correcting paths in ${JSON_FILE}..."
echo "Removing prefix: ${OLD_BASE_PATH}"

# Use sed to find all occurrences of the old base path and replace it with nothing.
# The '#' is used as a delimiter instead of '/' to avoid conflicts with the slashes in the path.
sed -i.bak "s#${OLD_BASE_PATH}##g" "$JSON_FILE"

if [ $? -eq 0 ]; then
    echo "Successfully corrected the paths in ${JSON_FILE}."
    echo "A secondary backup from sed was created as ${JSON_FILE}.bak"
    echo "Please try running your Python script's renewal function again."
else
    echo "An error occurred during path correction. Your original file is safe at ${BACKUP_FILE}."
fi
