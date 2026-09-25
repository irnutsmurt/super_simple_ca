#!/usr/bin/env python3
"""
Standalone Migration Script for SuperSimpleCA

This script migrates an old SuperSimpleCA setup (JSON database, old directory structure)
to the new ca_manager application format (SQLite database, new 'data' directory structure).

**SAFETY:**
- This script is designed to be run ONCE.
- Its VERY FIRST action is to create a complete backup of the old structure.
- It will NOT run if it detects that a migration has already been performed.

**INSTRUCTIONS:**
1. Place this script in the root of your old project, alongside the 'ca', 'certs',
   and the new 'ca_manager' directories.
2. Run the script with: python3 migrate.py
3. Follow the prompts.
"""
import os
import sys
import shutil
import json
import sqlite3
import logging
from datetime import datetime

# --- Configuration ---
# This script assumes it's in the root of the old project structure.
OLD_ROOT = '.'
NEW_APP_DIR = 'ca_manager'
NEW_DATA_DIR = os.path.join(NEW_APP_DIR, 'data')
BACKUP_DIR = '_migration_backup'

# Setup basic logging to the console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_backup():
    """Creates a complete backup of the old structure."""
    logging.info(f"Creating a complete backup of the current state into './{BACKUP_DIR}/'")
    if os.path.exists(BACKUP_DIR):
        logging.warning(f"Backup directory '{BACKUP_DIR}' already exists. Removing it to create a fresh backup.")
        shutil.rmtree(BACKUP_DIR)
    
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # List of old directories/files to back up
    items_to_backup = ['ca', 'certs', 'configs', 'crl', 'db', 'logs', 'super_simple_ca.py']
    
    for item in items_to_backup:
        src_path = os.path.join(OLD_ROOT, item)
        dest_path = os.path.join(BACKUP_DIR, item)
        if os.path.exists(src_path):
            try:
                if os.path.isdir(src_path):
                    shutil.copytree(src_path, dest_path)
                else:
                    shutil.copy2(src_path, dest_path)
            except Exception as e:
                logging.error(f"Failed to back up '{item}'. Aborting. Error: {e}")
                sys.exit(1)
        else:
            logging.warning(f"Skipping backup for '{item}' as it does not exist.")
            
    logging.info("Backup created successfully.")

def setup_new_directories():
    """Creates the new data directory structure for the ca_manager app."""
    logging.info(f"Setting up new directory structure inside '{NEW_DATA_DIR}'...")
    try:
        # These paths are based on the new app's config.py
        os.makedirs(os.path.join(NEW_DATA_DIR, 'ca'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'certs'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'crl'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'db', 'backup'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'logs'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'configs'), exist_ok=True)
        os.makedirs(os.path.join(NEW_DATA_DIR, 'revoked'), exist_ok=True)
        logging.info("New directory structure created.")
    except Exception as e:
        logging.error(f"Failed to create new directories. Aborting. Error: {e}")
        sys.exit(1)

def migrate_database():
    """Reads the old JSON DB and writes to the new SQLite DB."""
    old_db_path = os.path.join(OLD_ROOT, 'db', 'cert_database.json')
    new_db_path = os.path.join(NEW_DATA_DIR, 'db', 'certificates.db')
    
    logging.info(f"Migrating database from '{old_db_path}' to '{new_db_path}'...")

    if not os.path.exists(old_db_path):
        logging.error(f"Old database '{old_db_path}' not found. Aborting.")
        sys.exit(1)

    with open(old_db_path, 'r') as f:
        old_data = json.load(f)

    # 1. Initialize the new SQLite database schema
    conn = sqlite3.connect(new_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT NOT NULL UNIQUE,
            common_name TEXT NOT NULL, cert_type TEXT NOT NULL,
            status TEXT NOT NULL, issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, revoked_at TEXT,
            cert_path TEXT NOT NULL, key_path TEXT NOT NULL
        );
    """)
    
    # 2. Iterate and insert data
    for serial, data in old_data.items():
        logging.info(f"Migrating record for CN='{data['common_name']}' (Serial: {serial})")
        
        # Translate old fields to new schema
        status = 'revoked' if data.get('revoked', False) else 'valid'
        
        # Handle new filename convention
        new_cert_filename = data['cert_file'].replace('.cert.pem', '.crt').replace('.pem', '.crt')
        new_key_filename = data['key_file'].replace('.key.pem', '.key').replace('.pem', '.key')

        # Paths should be relative to the new app's root dir ('ca_manager/')
        rel_cert_path = os.path.join('data', new_cert_filename)
        rel_key_path = os.path.join('data', new_key_filename)
        
        cursor.execute("""
            INSERT INTO certificates (serial, common_name, cert_type, status, issued_at, 
                                      expires_at, revoked_at, cert_path, key_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            serial,
            data['common_name'],
            data['type'],
            status,
            data['issued'],
            data['expires'],
            None, # Old DB didn't track revocation date, so we leave it null
            rel_cert_path,
            rel_key_path
        ))
    
    conn.commit()
    conn.close()
    logging.info("Database migration completed successfully.")
    return old_data

def migrate_files(db_data):
    """Copies and renames files from the old structure to the new one."""
    logging.info("Migrating all certificate, key, and CA files...")

    # 1. Migrate core CA and OpenSSL DB files
    core_files = {
        'ca/ca.key.pem': 'ca/ca.key.pem',
        'ca/ca.cert.pem': 'ca/ca.cert.pem',
        'db/index.txt': 'db/index.txt',
        'db/serial': 'db/serial',
        'db/crlnumber': 'db/crlnumber'
    }
    for old_path, new_path in core_files.items():
        src = os.path.join(OLD_ROOT, old_path)
        dest = os.path.join(NEW_DATA_DIR, new_path)
        if os.path.exists(src):
            shutil.copy2(src, dest)
            logging.info(f"Copied '{src}' to '{dest}'")

    # 2. Migrate certificate and key files based on DB records
    for serial, data in db_data.items():
        # --- BUG FIX IS HERE ---
        # We now intelligently determine the source directory based on revocation status.
        is_revoked = data.get('revoked', False)
        
        cert_filename = os.path.basename(data['cert_file'])
        key_filename = os.path.basename(data['key_file'])
        
        if is_revoked:
            # For revoked certs, the old script moved them to 'revokedcerts'.
            # The JSON path is stale, so we build the correct path.
            source_dir = os.path.join(OLD_ROOT, 'certs', 'revokedcerts')
            dest_dir = os.path.join(NEW_DATA_DIR, 'revoked')
        else:
            # For valid certs, the path in the JSON is correct relative to the old root.
            source_dir = os.path.join(OLD_ROOT, 'certs')
            dest_dir = os.path.join(NEW_DATA_DIR, 'certs')
            
        old_cert_path = os.path.join(source_dir, cert_filename)
        old_key_path = os.path.join(source_dir, key_filename)

        # Determine new filename with new extension
        new_cert_filename = cert_filename.replace('.cert.pem', '.crt').replace('.pem', '.crt')
        new_key_filename = key_filename.replace('.key.pem', '.key').replace('.pem', '.key')

        new_cert_path = os.path.join(dest_dir, new_cert_filename)
        new_key_path = os.path.join(dest_dir, new_key_filename)

        # Copy and rename cert file
        if os.path.exists(old_cert_path):
            shutil.copy2(old_cert_path, new_cert_path)
            logging.info(f"Copied and renamed '{old_cert_path}' -> '{new_cert_path}'")
        else:
            logging.warning(f"Source file not found, skipping: {old_cert_path}")

        # Copy and rename key file
        if os.path.exists(old_key_path):
            shutil.copy2(old_key_path, new_key_path)
            logging.info(f"Copied and renamed '{old_key_path}' -> '{new_key_path}'")
        else:
            logging.warning(f"Source file not found, skipping: {old_key_path}")

    logging.info("File migration completed.")


def main():
    """Main migration process."""
    print("="*60)
    print(" SuperSimpleCA to CA_Manager Migration Script")
    print("="*60)
    print("This script will migrate your old JSON-based CA to the new")
    print("SQLite-based application structure.")
    print("\n** WARNING **")
    print("1. A full backup of your existing CA will be created in:")
    print(f"   './{BACKUP_DIR}/'")
    print("2. This script should only be run ONCE.")
    print("3. Ensure no CA operations are running while this is in progress.")
    print("-" * 60)

    # Pre-flight checks
    if not os.path.exists('cert_database.json') and not os.path.exists('db/cert_database.json'):
         logging.error("Could not find 'cert_database.json'. Are you in the right directory?")
         sys.exit(1)
    if not os.path.exists(NEW_APP_DIR):
        logging.error(f"The new application directory '{NEW_APP_DIR}' was not found.")
        sys.exit(1)
    if os.path.exists(NEW_DATA_DIR):
        logging.error(f"The new data directory '{NEW_DATA_DIR}' already exists. Migration may have been run before. Aborting.")
        sys.exit(1)

    try:
        if input("Do you wish to proceed with the migration? (yes/no): ").lower() != 'yes':
            print("Migration cancelled by user.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nMigration cancelled by user.")
        sys.exit(0)

    # --- Start Migration ---
    create_backup()
    setup_new_directories()
    db_data = migrate_database()
    migrate_files(db_data)
    
    # --- Final Instructions ---
    print("\n" + "="*60)
    print(" MIGRATION COMPLETED SUCCESSFULLY!")
    print("="*60)
    print("Your new CA data is located in:")
    print(f"  -> {NEW_DATA_DIR}")
    print("\nYour old CA has been safely backed up to:")
    print(f"  -> {BACKUP_DIR}")
    print("\nNext Steps:")
    print(f"1. Verify the new application works correctly by running:")
    print(f"   cd {NEW_APP_DIR}")
    print(f"   python main.py")
    print("2. Check the certificate list (Option 6) to ensure all certs appear.")
    print("3. Once you are confident everything works, you may manually delete")
    print("   the old directories (ca, certs, configs, etc.) and this script.")
    print("\nIt is STRONGLY recommended to keep the backup folder for a while.")
    print("="*60)


if __name__ == "__main__":
    main()
