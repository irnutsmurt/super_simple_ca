#!/bin/bash

# A script to correct the absolute file paths within an OpenSSL index.txt file.
# It replaces the hardcoded directory with a relative path and creates a
# date-stamped backup of the original file before making changes.

# --- Configuration ---
# The directory where your 'db' folder is located.
# The script assumes it is in the same directory by default.
CA_BASE_DIR="$(pwd)"
DB_DIR="${CA_BASE_DIR}/db"
INDEX_FILE="${DB_DIR}/index.txt"

# Generate a timestamp for the backup file, e.g., "10-21-25"
TIMESTAMP=$(date +%m-%d-%y)
BACKUP_FILE="${DB_DIR}/${TIMESTAMP}.index.txt.bak"

# --- Safety Check ---
if [ ! -f "$INDEX_FILE" ]; then
    echo "ERROR: Cannot find index.txt at ${INDEX_FILE}"
    echo "Please run this script from your main CA directory (the one containing 'db', 'certs', etc.)."
    exit 1
fi

# --- Backup ---
echo "Backing up your existing index.txt to ${BACKUP_FILE}..."

# Check if a backup for today already exists to prevent accidental overwrites
if [ -f "$BACKUP_FILE" ]; then
    echo "WARNING: A backup for today already exists at ${BACKUP_FILE}."
    read -p "Do you want to overwrite it? (y/n): " -n 1 -r
    echo # Move to a new line
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborting script. No changes were made."
        exit 1
    fi
fi

cp "$INDEX_FILE" "$BACKUP_FILE"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create a backup. Aborting."
    exit 1
fi
echo "Backup successful."

# --- Path Correction ---
echo "Correcting paths in index.txt..."

# This awk command does the following:
# -F'\t'       : Sets the field separator to a tab character.
# -v OFS='\t'  : Sets the output field separator to a tab.
# '{ ... }'    : This block of code runs for each line in the file.
# '$5 ~ /^\//' : This is a condition that checks if the 5th column (the filename) starts with a '/'.
#               This prevents the script from altering lines that are already correct or have a different format.
# 'gsub(/.*\//, "", $5)' : If the condition is met, this function globally substitutes the longest match of
#                         'anything ending in a slash' with 'nothing' in the 5th column.
#                         Effectively, it strips the directory path.
# '1'          : This is a shorthand in awk that means 'print the current line (after modifications)'.

awk -F'\t' -v OFS='\t' '{
    if ($5 ~ /^\//) {
        gsub(/.*\//, "", $5)
    }
    print
}' "$BACKUP_FILE" > "$INDEX_FILE"

if [ $? -eq 0 ]; then
    echo "Successfully corrected the paths in ${INDEX_FILE}."
    echo "Please review the new file to ensure it looks correct. Your original file is safe at ${BACKUP_FILE}."
else
    echo "An error occurred during path correction. Your original file is safe at ${BACKUP_FILE}."
fi
