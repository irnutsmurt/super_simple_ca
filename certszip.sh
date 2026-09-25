#!/bin/bash

# A script to zip certificate files, renaming some in the process.

# --- Configuration ---
# Set the directory where your certificate files are located.
SOURCE_DIR="certs"

# Set the desired name for the final zip file.
ZIP_FILENAME="certs_archive.zip"
# --- End of Configuration ---

# Create a temporary directory to stage files for zipping.
# The 'mktemp -d' command creates a unique temporary directory to prevent conflicts.
TEMP_DIR=$(mktemp -d)

# Check if the temporary directory was created successfully.
if [[ ! -d "$TEMP_DIR" ]]; then
    echo "Error: Could not create a temporary directory."
    exit 1
fi

# Use a trap to ensure the temporary directory is cleaned up when the script exits,
# even if an error occurs.
trap 'rm -rf "$TEMP_DIR"' EXIT

# --- File Staging ---
# Copy and rename the files that have .cert.pem and .key.pem extensions.
# The 'cp' command is used here to copy and rename the files into our temporary staging area.
echo "Staging and renaming files..."
cp "$SOURCE_DIR/radarr.cert.pem" "$TEMP_DIR/radarr.crt"
cp "$SOURCE_DIR/radarr.key.pem" "$TEMP_DIR/radarr.key"
cp "$SOURCE_DIR/sonarr.cert.pem" "$TEMP_DIR/sonarr.crt"
cp "$SOURCE_DIR/sonarr.key.pem" "$TEMP_DIR/sonarr.key"

# Copy the rest of the certificate files directly into the temporary directory.
cp "$SOURCE_DIR/bazarr.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/bazarr.key" "$TEMP_DIR/"
cp "$SOURCE_DIR/lidarr.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/lidarr.key" "$TEMP_DIR/"
cp "$SOURCE_DIR/mealie.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/mealie.key" "$TEMP_DIR/"
cp "$SOURCE_DIR/prowlarr.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/prowlarr.key" "$TEMP_DIR/"
cp "$SOURCE_DIR/qbittorrent.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/qbittorrent.key" "$TEMP_DIR/"
cp "$SOURCE_DIR/romm.crt" "$TEMP_DIR/"
cp "$SOURCE_DIR/romm.key" "$TEMP_DIR/"

# --- Zipping ---
# Create the zip file from the contents of the temporary directory.
# The '-j' flag, or --junk-paths, prevents the zip command from including the directory structure.
echo "Creating the zip archive..."
zip -j "$ZIP_FILENAME" "$TEMP_DIR"/*

echo "Successfully created '$ZIP_FILENAME'"

# The 'trap' command will automatically handle the cleanup of the temporary directory.
