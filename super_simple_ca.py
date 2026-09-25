#!/usr/bin/env python3
"""
Certificate Authority Management Script

This script provides a user-friendly, menu-driven interface for managing a Certificate Authority (CA) using OpenSSL.
It caters to both novice users who require guidance and power users who prefer command-line operations.

Author: Your Name
Date: 2023-10-05
"""

import os
import sys
import subprocess
import logging
import argparse
import shutil
import platform
import json
from datetime import datetime, timedelta
import getpass  # Imported for secure passphrase input

try:
    import readline
except ImportError:
    pass  # readline not available on Windows

# Check for required Python libraries
REQUIRED_LIBS = ['argparse', 'subprocess', 'logging', 'json']

# Global Variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE_DIR, 'ca')
CERTS_DIR = os.path.join(BASE_DIR, 'certs')
CRL_DIR = os.path.join(BASE_DIR, 'crl')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
DB_DIR = os.path.join(BASE_DIR, 'db')
CONFIGS_DIR = os.path.join(BASE_DIR, 'configs')
DATABASE_FILE = os.path.join(DB_DIR, 'cert_database.json')
OPENSSL_CONF = os.path.join(CONFIGS_DIR, 'openssl.cnf')
REVOKED_CERTS_DIR = os.path.join(CERTS_DIR, 'revokedcerts')
DEFAULT_VALIDITY_DAYS = 825  # Default validity period if not specified

# Define backup directory
DB_BACKUP_DIR = os.path.join(DB_DIR, 'backup')

# Ensure necessary directories exist and have correct permissions
DIRECTORIES = [CA_DIR, CERTS_DIR, REVOKED_CERTS_DIR, CRL_DIR, LOGS_DIR, DB_DIR, CONFIGS_DIR, DB_BACKUP_DIR]

for directory in DIRECTORIES:
    if not os.path.exists(directory):
        os.makedirs(directory)
    # Set permissions to ensure the script can write to these directories
    os.chmod(directory, 0o700)

# Set up logging
LOG_FILE = os.path.join(LOGS_DIR, 'ca_management.log')

logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Helper Functions
def check_dependencies():
    """Check if OpenSSL is installed."""
    try:
        subprocess.check_output(['openssl', 'version'])
    except FileNotFoundError:
        logging.error("OpenSSL is not installed.")
        install_openssl()
    except subprocess.CalledProcessError:
        logging.error("OpenSSL is not installed or not functioning properly.")
        install_openssl()

def install_openssl():
    """Guide the user to install OpenSSL."""
    os_name = platform.system()
    if os_name == 'Linux':
        choice = input("OpenSSL is not installed. Would you like to install it now? (yes/no): ")
        if choice.lower() in ['yes', 'y']:
            try:
                subprocess.check_call(['sudo', 'apt-get', 'install', '-y', 'openssl'])
                logging.info("OpenSSL installed successfully.")
            except Exception as e:
                logging.error(f"Failed to install OpenSSL: {e}")
                sys.exit(1)
        else:
            logging.info("Please install OpenSSL using your package manager (e.g., sudo apt-get install openssl).")
            sys.exit(1)
    elif os_name == 'Darwin':
        choice = input("OpenSSL is not installed. Would you like to install it now via Homebrew? (yes/no): ")
        if choice.lower() in ['yes', 'y']:
            try:
                subprocess.check_call(['brew', 'install', 'openssl'])
                logging.info("OpenSSL installed successfully.")
            except Exception as e:
                logging.error(f"Failed to install OpenSSL: {e}")
                sys.exit(1)
        else:
            logging.info("Please install OpenSSL using Homebrew (e.g., brew install openssl).")
            sys.exit(1)
    else:
        logging.info("Please install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html")
        sys.exit(1)

def is_ca_initialized():
    """Check if the CA is already initialized."""
    ca_key = os.path.join(CA_DIR, 'ca.key.pem')
    ca_cert = os.path.join(CA_DIR, 'ca.cert.pem')
    return os.path.exists(ca_key) and os.path.exists(ca_cert)

def find_valid_cert_by_subject(subject):
    """
    Parses the index.txt file to find a valid certificate by its subject.
    Returns the serial and common name if found, otherwise None, None.
    """
    index_file = os.path.join(DB_DIR, 'index.txt')
    if not os.path.exists(index_file):
        return None, None

    with open(index_file, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            # V, Expiry, RevocationDate, Serial, Filename, Subject
            if len(parts) >= 6 and parts[0] == 'V' and subject in parts[5]:
                serial = parts[3]
                # Extract CN from the subject string like '/.../CN=jellyfin/...'
                cn_part = [s for s in parts[5].split('/') if s.startswith('CN=')]
                if cn_part:
                    common_name = cn_part[0].split('=')[1]
                    return serial, common_name
    return None, None

def generate_openssl_conf():
    """Generate the OpenSSL configuration file."""
    openssl_conf_content = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {BASE_DIR}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/certs
database          = {os.path.join(DB_DIR, 'index.txt')}
serial            = {os.path.join(DB_DIR, 'serial')}
RANDFILE          = $dir/private/.rand
private_key       = {os.path.join(CA_DIR, 'ca.key.pem')}
certificate       = {os.path.join(CA_DIR, 'ca.cert.pem')}
crlnumber         = {os.path.join(DB_DIR, 'crlnumber')}
crl               = {os.path.join(CRL_DIR, 'crl.pem')}
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose
copy_extensions   = copy
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]
C   = US
ST  = Example State
L   = Example City
O   = Example Homelab
OU  = Homelab
CN  = Example Homelab CA

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always
"""
    with open(OPENSSL_CONF, 'w') as f:
        f.write(openssl_conf_content)

def initialize_ca():
    """Initialize the Certificate Authority."""
    logging.info("Initializing Certificate Authority...")
    ca_key = os.path.join(CA_DIR, 'ca.key.pem')
    ca_cert = os.path.join(CA_DIR, 'ca.cert.pem')
    ca_p7b = os.path.join(CA_DIR, 'ca.cert.p7b')  # Path for the .p7b file
    ca_pem = os.path.join(CA_DIR, 'ca.pem')        # Path for the ca.pem file

    if os.path.exists(ca_key) and os.path.exists(ca_cert):
        logging.info("CA already initialized.")
        return

    country = input("Enter Country Name (2 letter code) [US]: ") or "US"
    state = input("Enter State or Province Name [Example State]: ") or "Example State"
    locality = input("Enter Locality Name [Example City]: ") or "Example City"
    organization = input("Enter Organization Name [Example Homelab]: ") or "Example Homelab"
    organizational_unit = input("Enter Organizational Unit Name [Homelab]: ") or "Homelab"
    common_name = input("Enter Common Name [Example Homelab CA]: ") or "Example Homelab CA"
    email = input("Enter Email Address [admin@example.com]: ") or "admin@example.com"

    # Ask if the user wants to protect the CA key with a passphrase
    use_passphrase_input = input("Do you want to protect your CA private key with a passphrase? (yes/no) [yes]: ").strip().lower() or "yes"
    use_passphrase = use_passphrase_input in ['yes', 'y']

    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"

    # Generate private key
    if use_passphrase:
        # Encrypted private key
        while True:
            ca_passphrase = getpass.getpass(f"Enter pass phrase for {ca_key}: ")
            verify_passphrase = getpass.getpass(f"Verifying - Enter pass phrase for {ca_key}: ")
            if ca_passphrase == verify_passphrase:
                break
            else:
                logging.error("Passphrases do not match. Please try again.")
        subprocess.run([
            'openssl', 'genrsa', '-aes256', '-passout', f'pass:{ca_passphrase}', '-out', ca_key, '4096'
        ])
    else:
        # Unencrypted private key
        subprocess.run([
            'openssl', 'genrsa', '-out', ca_key, '4096'
        ])
    os.chmod(ca_key, 0o400)

    # Generate root certificate
    if use_passphrase:
        print("Please enter your passphrase to sign your new CA certificate.")
    subprocess.run([
        'openssl', 'req', '-config', OPENSSL_CONF, '-key', ca_key, '-new', '-x509',
        '-days', '3650', '-sha256', '-extensions', 'v3_ca', '-out', ca_cert, '-subj', subject,
        *(['-passin', f'pass:{ca_passphrase}'] if use_passphrase else [])
    ])
    os.chmod(ca_cert, 0o444)

    # Generate .p7b version of the CA certificate
    subprocess.run([
        'openssl', 'crl2pkcs7', '-nocrl', '-certfile', ca_cert, '-out', ca_p7b
    ])
    os.chmod(ca_p7b, 0o444)
    logging.info(f"Generated CA certificate in P7B format at {ca_p7b}")

    # Generate ca.pem by copying ca.cert.pem
    shutil.copy(ca_cert, ca_pem)
    os.chmod(ca_pem, 0o444)
    logging.info(f"Generated CA certificate in PEM format at {ca_pem}")

    # Initialize the database files
    with open(os.path.join(DB_DIR, 'index.txt'), 'w') as f:
        pass
    with open(os.path.join(DB_DIR, 'serial'), 'w') as f:
        f.write('1000\n')
    with open(os.path.join(DB_DIR, 'crlnumber'), 'w') as f:
        f.write('1000\n')

    logging.info("CA initialized successfully.")

def load_database():
    """Load the certificate database."""
    if not os.path.exists(DATABASE_FILE):
        return {}
    with open(DATABASE_FILE, 'r') as f:
        return json.load(f)

def save_database(db):
    """Save the certificate database."""
    with open(DATABASE_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def create_certificate(prefilled_common_name=None):
    """
    Create a new certificate. Can accept a prefilled common name to skip the prompt.
    """
    if prefilled_common_name:
        logging.info(f"Recreating certificate for: {prefilled_common_name}")
        common_name = prefilled_common_name
    else:
        logging.info("Creating a new certificate...")
        common_name = input("Enter Common Name (e.g., domain name or user name): ").strip()

    if not common_name:
        logging.error("Common Name cannot be empty.")
        return

    print("\nCertificate Types:")
    print("1. Server Certificate")
    print("2. Client Certificate")
    cert_type_input = input("Enter certificate type (1 for Server, 2 for Client): ").strip()
    if cert_type_input == '1':
        cert_type = 'server'
        extensions = 'server_cert'
    elif cert_type_input == '2':
        cert_type = 'client'
        extensions = 'usr_cert'
    else:
        logging.error("Invalid certificate type selection.")
        return

    # Using defaults for faster recreation
    country = input("Enter Country Name (2 letter code) [US]: ") or "US"
    state = input("Enter State or Province Name [Example State]: ") or "Example State"
    locality = input("Enter Locality Name [Example City]: ") or "Example City"
    organization = input("Enter Organization Name [Example Homelab]: ") or "Example Homelab"
    organizational_unit = input("Enter Organizational Unit Name [Homelab]: ") or "Homelab"
    email = input("Enter Email Address [admin@example.com]: ") or "admin@example.com"

    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"

    while True:
        validity_input = input(f"Enter certificate validity period in days [{DEFAULT_VALIDITY_DAYS}]: ").strip() or str(DEFAULT_VALIDITY_DAYS)
        try:
            validity_days = int(validity_input)
            if validity_days <= 0:
                raise ValueError
            break
        except ValueError:
            logging.error("Please enter a positive integer for the validity period.")

    san_input = input("Enter Subject Alternative Names (SANs) separated by commas (e.g., DNS:www.example.com, IP:192.168.1.1): ").strip()
    san_list = [san.strip() for san in san_input.split(',')] if san_input else []

    key_file = os.path.join(CERTS_DIR, f"{common_name}.key")
    csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr")
    cert_file = os.path.join(CERTS_DIR, f"{common_name}.crt")

    # The rest of the function remains the same, just copy it from your existing one...
    # ... (generate key, generate CSR, sign cert, update database)
    # ... This is just a placeholder for brevity

    # Generate private key, CSR, sign the cert, and update the database
    # (The following is the logic from the original function, ensure it's here)
    result = subprocess.run(['openssl', 'genrsa', '-out', key_file, '2048'], stderr=subprocess.PIPE)
    os.chmod(key_file, 0o600)

    san_file = os.path.join(CONFIGS_DIR, f"{common_name}_san.cnf")
    with open(san_file, 'w') as san_conf:
        san_conf.write(f"""
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[ req_distinguished_name ]
C  = {country}
ST = {state}
L  = {locality}
O  = {organization}
OU = {organizational_unit}
CN = {common_name}

[ v3_req ]
subjectAltName = {', '.join(san_list)}
""")

    subprocess.run(['openssl', 'req', '-key', key_file, '-new', '-out', csr_file, '-config', san_file])

    ca_passphrase_sign = getpass.getpass("Enter CA private key passphrase to sign the new certificate: ")
    subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-batch', '-extensions', extensions,
        '-days', str(validity_days), '-notext', '-md', 'sha256', '-in', csr_file, '-out', cert_file,
        '-passin', f'pass:{ca_passphrase_sign}'
    ])
    os.chmod(cert_file, 0o644)

    db = load_database()
    serial_number = get_certificate_serial(cert_file)
    db[serial_number] = {
        'common_name': common_name, 'type': cert_type, 'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=validity_days)).isoformat(), 'revoked': False,
        'key_file': os.path.relpath(key_file, BASE_DIR), 'cert_file': os.path.relpath(cert_file, BASE_DIR),
    }
    save_database(db)

    logging.info(f"{cert_type.capitalize()} certificate for {common_name} created successfully.")

def get_certificate_serial(cert_file):
    """Get the serial number from a certificate file."""
    result = subprocess.run(['openssl', 'x509', '-in', cert_file, '-noout', '-serial'], stdout=subprocess.PIPE)
    serial_line = result.stdout.decode().strip()
    serial_number = serial_line.split('=')[1]
    return serial_number

def revoke_certificate():
    """Revoke an existing certificate."""
    logging.info("Revoking a certificate...")
    db = load_database()
    valid_certs = {k: v for k, v in db.items() if not v.get('revoked')}

    if not valid_certs:
        logging.info("No valid certificates found.")
        return

    print("Select a certificate to revoke:")
    for idx, (serial, cert_info) in enumerate(valid_certs.items(), 1):
        print(f"{idx}. {cert_info['common_name']} (Serial: {serial})")

    try:
        choice = int(input("Enter your choice: "))
    except ValueError:
        logging.error("Invalid input. Please enter a number.")
        return

    if choice < 1 or choice > len(valid_certs):
        logging.error("Invalid choice.")
        return

    serial_to_revoke = list(valid_certs.keys())[choice - 1]

    ca_passphrase_revoke = getpass.getpass("Enter CA private key passphrase to revoke the certificate: ")
    cert_file = os.path.join(BASE_DIR, db[serial_to_revoke]['cert_file'])
    result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-revoke', cert_file,
        '-passin', f'pass:{ca_passphrase_revoke}'
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return

    db[serial_to_revoke]['revoked'] = True
    save_database(db)

    key_file = os.path.join(BASE_DIR, db[serial_to_revoke]['key_file'])
    cert_common_name = db[serial_to_revoke]['common_name']
    files_to_move = [key_file, cert_file]
    for file_path in files_to_move:
        if os.path.exists(file_path):
            file_name = os.path.basename(file_path)
            new_path = os.path.join(REVOKED_CERTS_DIR, file_name)
            shutil.move(file_path, new_path)
            logging.info(f"Moved {file_path} to {new_path}")

    # --- MODIFIED EXTENSION ---
    csr_file = os.path.join(CERTS_DIR, f"{cert_common_name}.csr")
    # --- END MODIFICATION ---
    if os.path.exists(csr_file):
        new_csr_path = os.path.join(REVOKED_CERTS_DIR, os.path.basename(csr_file))
        shutil.move(csr_file, new_csr_path)
        logging.info(f"Moved {csr_file} to {new_csr_path}")

    logging.info("Updating CRL...")
    update_crl(ca_passphrase_revoke)

    logging.info(f"Certificate with serial {serial_to_revoke} revoked successfully.")

def update_crl(ca_passphrase):
    """Update the Certificate Revocation List."""
    crl_file = os.path.join(CRL_DIR, 'crl.pem')

    result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-gencrl', '-out', crl_file,
        '-passin', f'pass:{ca_passphrase}'
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return
    logging.info("CRL updated successfully.")

def install_root_certificate():
    """Provide guidance on installing the root certificate."""
    logging.info("Guiding user to install the root certificate...")
    ca_p7b = os.path.join(CA_DIR, 'ca.cert.p7b')  # Updated to use .p7b
    os_name = platform.system()

    if os_name == 'Windows':
        logging.info("Windows Root Certificate Installation Guide:")
        print("1. Open the Microsoft Management Console (mmc.exe).")
        print("2. Add the Certificates snap-in for the Local Computer account.")
        print(f"3. Import the CA certificate file '{ca_p7b}' into the 'Trusted Root Certification Authorities' store.")
    elif os_name == 'Darwin':
        logging.info("macOS Root Certificate Installation Guide:")
        print("1. Open 'Keychain Access' application.")
        print(f"2. Drag and drop the CA certificate file '{ca_p7b}' into the 'System' keychain.")
        print("3. Trust the certificate by setting 'When using this certificate' to 'Always Trust'.")
    elif os_name == 'Linux':
        logging.info("Linux Root Certificate Installation Guide:")
        print(f"1. Copy the CA certificate file '{ca_p7b}' to your system's certificate store (e.g., '/usr/local/share/ca-certificates/').")
        print(f"2. Run 'sudo cp {ca_p7b} /usr/local/share/ca-certificates/'.")
        print("3. Update the certificate store using 'sudo update-ca-certificates'.")
    else:
        logging.info("Operating system not recognized. Please refer to your system's documentation.")

def get_certificate_details(cert_path):
    """
    Parses a certificate file to extract its subject and Subject Alternative Names (SANs)
    by parsing the full text output of the certificate. This is the most compatible method.
    Returns (subject, san_list) on success, or (None, None) on failure.
    """
    if not os.path.exists(cert_path):
        logging.error(f"Certificate file not found at {cert_path}")
        return None, None

    # This is the single, highly-compatible command you verified works.
    command = [
        'openssl', 'x509', '-noout', '-text', '-in', cert_path
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        subject = None
        san_list = []
        # A state flag to know when we are in the SAN section of the output
        in_san_section = False

        for line in output.splitlines():
            # Stop parsing for SANs if we've left the section
            if in_san_section and not line.strip().startswith(('DNS:', 'IP Address:')):
                in_san_section = False

            # --- Parse the Subject ---
            # We look for the "Subject:" line, being careful not to match other lines.
            if 'Subject:' in line and 'Public Key Info' not in line:
                # Extract the raw subject string: "C = US, ST = Example State, CN = host"
                subject_raw = line.split('Subject:', 1)[1].strip()
                # Reformat it to the slash-separated format the rest of the script expects:
                # "/C=US/ST=Example State/CN=host"
                subject_parts = [part.strip().replace(' = ', '=') for part in subject_raw.split(',')]
                subject = '/' + '/'.join(subject_parts)
                continue

            # --- Parse the Subject Alternative Names (SANs) ---
            # Look for the header that marks the start of the SAN section.
            if 'X509v3 Subject Alternative Name:' in line:
                in_san_section = True
                continue # The SANs are on the *next* line, so we skip to it.

            if in_san_section:
                # The SANs are on one or more indented lines, separated by commas.
                sans_on_line = [san.strip() for san in line.strip().split(',')]
                san_list.extend(sans_on_line)

        # Final cleanup to remove any empty entries
        san_list = [san for san in san_list if san]

        if subject is None:
            logging.error(f"Could not parse Subject from the certificate text for {cert_path}")
            return None, None

        return subject, san_list

    except subprocess.CalledProcessError as e:
        # This will catch failures if the certificate file is truly corrupt.
        logging.error(f"The 'openssl x509 -text' command failed for certificate {cert_path}.")
        logging.error(f"Failed Command: {' '.join(e.cmd)}")
        logging.error(f"OpenSSL Error Message: {e.stderr.strip()}")
        return None, None
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {cert_path}: {e}")
        return None, None

def perform_renewal(serial_number, ca_passphrase):
    """
    Performs the safe, two-phase renewal process for a single certificate,
    including removing the old entry from index.txt.
    Returns True on success, False on failure.
    """
    renewal_validity_days = 730

    db = load_database()
    if serial_number not in db or db[serial_number].get('revoked', False):
        logging.error(f"Certificate with serial {serial_number} not found or is already revoked.")
        return False

    old_cert_info = db[serial_number]
    common_name = old_cert_info['common_name']
    old_cert_file = os.path.join(BASE_DIR, old_cert_info['cert_file'])

    logging.info(f"--- Starting renewal for '{common_name}' (Serial: {serial_number}) ---")

    logging.info("Phase 1: Preparing for renewal...")
    subject, san_list = get_certificate_details(old_cert_file)
    if subject is None:
        logging.error(f"ABORTING renewal for '{common_name}': Could not extract details from old certificate.")
        return False
    logging.info("Successfully extracted details from old certificate.")

    logging.info("Phase 2: Decommissioning old certificate...")
    timestamp = datetime.now().strftime('%m-%d-%y_%H-%M-%S')
    index_file_path = os.path.join(DB_DIR, 'index.txt')
    backup_file = os.path.join(DB_BACKUP_DIR, f"{timestamp}.index.txt.bak")
    shutil.copy(index_file_path, backup_file)
    logging.info(f"Database backed up to {backup_file}")

    revoke_result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-revoke', old_cert_file,
        '-passin', f'pass:{ca_passphrase}'
    ], capture_output=True, text=True)
    if revoke_result.returncode != 0:
        logging.error(f"Failed to revoke old certificate for '{common_name}'. Aborting.")
        logging.error(f"OpenSSL Error: {revoke_result.stderr}")
        return False
    logging.info("Old certificate successfully revoked.")

    update_crl(ca_passphrase)

    try:
        with open(index_file_path, 'r') as f:
            lines = f.readlines()
        with open(index_file_path, 'w') as f:
            for line in lines:
                if line.strip() and line.strip().split('\t')[3] != serial_number:
                    f.write(line)
        logging.info(f"Removed entry for serial {serial_number} from index.txt.")
    except Exception as e:
        logging.error(f"Failed to remove entry from index.txt: {e}. Aborting to prevent inconsistent state.")
        shutil.copy(backup_file, index_file_path)
        return False

    old_key_file = os.path.join(BASE_DIR, old_cert_info['key_file'])
    # --- MODIFIED EXTENSION LOGIC ---
    old_csr_file = old_cert_file.replace('.crt', '.csr')
    # --- END MODIFICATION ---
    for file_path in [old_cert_file, old_key_file, old_csr_file]:
        if os.path.exists(file_path):
            shutil.move(file_path, os.path.join(REVOKED_CERTS_DIR, os.path.basename(file_path)))
    logging.info("Old certificate files moved to revoked directory.")

    logging.info("Phase 3: Creating new certificate...")
    # --- MODIFIED EXTENSIONS ---
    new_key_file = os.path.join(CERTS_DIR, f"{common_name}.key")
    new_csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr")
    new_cert_file = os.path.join(CERTS_DIR, f"{common_name}.crt")
    # --- END MODIFICATION ---
    subprocess.run(['openssl', 'genrsa', '-out', new_key_file, '2048'])
    os.chmod(new_key_file, 0o600)

    subject_parts = {part.split('=')[0].strip(): part.split('=')[1].strip() for part in subject.strip('/').split('/') if '=' in part}
    san_conf_file = os.path.join(CONFIGS_DIR, f"{common_name}_san_renew.cnf")

    alt_names_content_list = []
    dns_count = 1
    ip_count = 1
    for i, san in enumerate(san_list):
        if san.startswith('DNS:'):
            alt_names_content_list.append(f"DNS.{dns_count} = {san.split(':', 1)[1]}")
            dns_count += 1
        elif san.startswith(('IP Address:', 'IP:')):
            alt_names_content_list.append(f"IP.{ip_count} = {san.split(':', 1)[1]}")
            ip_count += 1
    alt_names_content = '\n'.join(alt_names_content_list)

    with open(san_conf_file, 'w') as f:
        f.write(f"""
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C  = {subject_parts.get('C', '')}
ST = {subject_parts.get('ST', '')}
L  = {subject_parts.get('L', '')}
O  = {subject_parts.get('O', '')}
OU = {subject_parts.get('OU', '')}
CN = {subject_parts.get('CN', '')}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
{alt_names_content}
""")
    subprocess.run(['openssl', 'req', '-new', '-key', new_key_file, '-out', new_csr_file, '-config', san_conf_file])
    os.remove(san_conf_file)

    sign_result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-batch',
        '-extensions', 'usr_cert' if old_cert_info['type'] == 'client' else 'server_cert',
        '-days', str(renewal_validity_days), '-notext', '-md', 'sha256',
        '-in', new_csr_file, '-out', new_cert_file,
        '-passin', f'pass:{ca_passphrase}'
    ], capture_output=True, text=True)

    if sign_result.returncode != 0:
        logging.error(f"CRITICAL ERROR: Failed to sign the new certificate for '{common_name}' after removing the old entry.")
        logging.error("The CA may be in an inconsistent state. Please check the backup of index.txt.")
        logging.error(f"OpenSSL Error: {sign_result.stderr}")
        return False

    logging.info("Phase 3 COMPLETE: New certificate created successfully.")

    new_serial = get_certificate_serial(new_cert_file)
    if serial_number in db:
        db[serial_number]['revoked'] = True

    db[new_serial] = {
        'common_name': common_name,
        'type': old_cert_info['type'],
        'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=renewal_validity_days)).isoformat(),
        'revoked': False,
        # --- MODIFIED EXTENSIONS ---
        'key_file': os.path.relpath(new_key_file, BASE_DIR),
        'cert_file': os.path.relpath(new_cert_file, BASE_DIR),
        # --- END MODIFICATION ---
    }
    save_database(db)
    logging.info("JSON database updated.")

    logging.info(f"--- Renewal for '{common_name}' COMPLETE ---")
    return True

def renew_certificate_menu():
    """Displays a menu for renewing one or more certificates."""
    db = load_database()
    valid_certs = {k: v for k, v in db.items() if not v.get('revoked')}

    if not valid_certs:
        logging.info("No valid certificates available to renew.")
        return

    # ... (The certificate selection logic remains the same)
    print("\nSelect certificate(s) to renew:")
    cert_list = list(valid_certs.items())
    for idx, (serial, cert_info) in enumerate(cert_list, 1):
        try:
            expires_date = datetime.fromisoformat(cert_info['expires']).strftime('%Y-%m-%d')
            print(f"{idx}. {cert_info['common_name']} (Expires: {expires_date}, Serial: {serial})")
        except (ValueError, KeyError):
            print(f"{idx}. {cert_info.get('common_name', 'N/A')} (Invalid expiry date, Serial: {serial})")

    print("\nYou can select a single certificate (e.g., '5') or multiple (e.g., '1,3,4').")
    choice_str = input("Enter your selection(s): ").strip()
    # ... (The rest of the selection logic remains the same)
    try:
        selected_indices = [int(i.strip()) - 1 for i in choice_str.split(',')]
    except ValueError:
        logging.error("Invalid input. Please enter numbers separated by commas.")
        return

    serials_to_renew = [cert_list[idx][0] for idx in selected_indices if 0 <= idx < len(cert_list)]

    if not serials_to_renew:
        logging.info("No valid certificates selected.")
        return

    ca_passphrase = getpass.getpass("Enter CA private key passphrase: ")
    if not ca_passphrase:
        logging.error("Passphrase cannot be empty. Aborting renewal.")
        return

    logging.info(f"Preparing to renew {len(serials_to_renew)} certificate(s).")
    success_count = 0
    failed_renewals = []

    for serial in serials_to_renew:
        if perform_renewal(serial, ca_passphrase):
            success_count += 1
        else:
            common_name = db.get(serial, {}).get('common_name', f'Unknown (Serial: {serial})')
            failed_renewals.append(common_name)

    logging.info("--- Renewal Summary ---")
    logging.info(f"Successfully renewed: {success_count}")
    if failed_renewals:
        logging.info(f"Failed to renew: {len(failed_renewals)} ({', '.join(failed_renewals)})")
    else:
        logging.info("Failed to renew: 0")

    # --- NEW FEATURE: MANUAL RECREATION FOR FAILED CERTS ---
    if failed_renewals:
        choice = input("\nSome renewals failed. Would you like to attempt to recreate them manually? (yes/no): ").strip().lower()
        if choice in ['yes', 'y']:
            for name in failed_renewals:
                print("-" * 20)
                if cleanup_failed_certificate(name):
                    create_certificate(prefilled_common_name=name)
                else:
                    logging.error(f"Could not perform cleanup for {name}. Skipping recreation.")

def _create_certificate_non_interactive(common_name, cert_type, validity_days, san_list, ca_passphrase):
    """Core non-interactive logic to create a single certificate."""
    extensions = 'server_cert' if cert_type == 'server' else 'usr_cert'
    subject = f"/CN={common_name}" # Simplified subject for bulk creation

    key_file = os.path.join(CERTS_DIR, f"{common_name}.key")
    csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr")
    cert_file = os.path.join(CERTS_DIR, f"{common_name}.crt")

    # Generate key and CSR
    subprocess.run(['openssl', 'genrsa', '-out', key_file, '2048'])
    os.chmod(key_file, 0o600)

    san_conf_content = f"""
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
CN = {common_name}
[ v3_req ]
subjectAltName = {', '.join(san_list)}
"""
    san_conf_file = os.path.join(CONFIGS_DIR, f"{common_name}_san_bulk.cnf")
    with open(san_conf_file, 'w') as f:
        f.write(san_conf_content)

    subprocess.run(['openssl', 'req', '-new', '-key', key_file, '-out', csr_file, '-config', san_conf_file])
    os.remove(san_conf_file)

    # Sign the certificate
    sign_result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-batch', '-extensions', extensions,
        '-days', str(validity_days), '-notext', '-md', 'sha256',
        '-in', csr_file, '-out', cert_file, '-passin', f'pass:{ca_passphrase}'
    ], capture_output=True, text=True)

    if sign_result.returncode != 0:
        logging.error(f"Failed to create certificate for '{common_name}'.")
        logging.error(f"OpenSSL Error: {sign_result.stderr}")
        return False

    # Update database
    db = load_database()
    serial = get_certificate_serial(cert_file)
    db[serial] = {
        'common_name': common_name, 'type': cert_type, 'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=validity_days)).isoformat(), 'revoked': False,
        'key_file': os.path.relpath(key_file, BASE_DIR), 'cert_file': os.path.relpath(cert_file, BASE_DIR),
    }
    save_database(db)
    logging.info(f"Successfully created certificate for '{common_name}'.")
    return True

def bulk_create_certificates():
    """Menu function for creating multiple server certificates from a list of names."""
    logging.info("--- Bulk Certificate Creation ---")
    names_input = input("Enter common names separated by commas (e.g., whiskey,tango,foxtrot): ").strip()
    if not names_input:
        logging.error("No names provided.")
        return

    base_domain = input("Enter a base domain (e.g., example.com): ").strip()
    if not base_domain:
        logging.error("Base domain cannot be empty.")
        return

    ip_input = input("Enter a single IP for all certs (optional, for reverse proxy): ").strip()
    if ip_input:
        logging.warning("The same IP address will be added to every certificate.")

    ca_passphrase = getpass.getpass("Enter CA private key passphrase (will be used for all creations): ")
    if not ca_passphrase:
        logging.error("Passphrase cannot be empty.")
        return

    names = [name.strip() for name in names_input.split(',')]
    success_count = 0
    failure_count = 0

    for name in names:
        fqdn = f"{name}.{base_domain}"
        san_list = [f"DNS:{fqdn}"]
        if ip_input:
            san_list.append(f"IP:{ip_input}")

        if _create_certificate_non_interactive(name, 'server', 730, san_list, ca_passphrase):
            success_count += 1
        else:
            failure_count += 1

    logging.info("--- Bulk Creation Summary ---")
    logging.info(f"Successfully created: {success_count}")
    logging.info(f"Failed to create: {failure_count}")

def cleanup_failed_certificate(common_name):
    """
    Finds and completely removes a certificate by its common name from the databases
    and archives its files. This is used to prepare for a clean recreation.
    Returns True on success, False on failure.
    """
    logging.info(f"Performing cleanup for failed certificate: {common_name}...")
    db = load_database()
    serial_to_remove = None
    cert_info = None

    # Find the certificate's serial number and info from the common name
    for serial, info in db.items():
        if info.get('common_name') == common_name:
            serial_to_remove = serial
            cert_info = info
            break

    if not serial_to_remove:
        logging.error(f"Could not find certificate '{common_name}' in the JSON database for cleanup.")
        return False

    # 1. Archive old files (.crt, .key, .csr)
    for key in ['cert_file', 'key_file']:
        if key in cert_info and cert_info[key]:
            file_path = os.path.join(BASE_DIR, cert_info[key])
            if os.path.exists(file_path):
                shutil.move(file_path, os.path.join(REVOKED_CERTS_DIR, os.path.basename(file_path)))
    csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr")
    if os.path.exists(csr_file):
        shutil.move(csr_file, os.path.join(REVOKED_CERTS_DIR, os.path.basename(csr_file)))
    logging.info(f"Archived old files for {common_name}.")

    # 2. Remove from JSON database
    del db[serial_to_remove]
    save_database(db)
    logging.info(f"Removed '{common_name}' from JSON database.")

    # 3. Remove from index.txt
    try:
        index_file_path = os.path.join(DB_DIR, 'index.txt')
        with open(index_file_path, 'r') as f:
            lines = f.readlines()
        with open(index_file_path, 'w') as f:
            for line in lines:
                # The serial number is the 4th field (index 3)
                if line.strip() and line.strip().split('\t')[3] != serial_to_remove:
                    f.write(line)
        logging.info(f"Removed entry for serial {serial_to_remove} from index.txt.")
    except Exception as e:
        logging.error(f"Failed to remove entry from index.txt: {e}. Manual cleanup may be required.")
        return False

    return True

def main_menu():
    """Display the main menu."""
    while True:
        print("\nCertificate Authority Management")
        print("1. Initialize CA")
        print("2. Create Certificate")
        print("3. Revoke Certificate")
        print("4. Install Root Certificate")
        print("5. Renew Certificate(s)")
        print("6. Bulk Create Server Certificates")
        print("7. Exit")

        choice = input("Enter your choice (1-7): ")

        if choice == '1':
            initialize_ca()
        elif choice == '2':
            create_certificate()
        elif choice == '3':
            revoke_certificate()
        elif choice == '4':
            install_root_certificate()
        elif choice == '5':
            renew_certificate_menu()
        elif choice == '6':
            bulk_create_certificates()
        elif choice == '7':
            logging.info("Exiting the script.")
            sys.exit(0)
        else:
            logging.error("Invalid choice. Please enter a number between 1 and 7.")

def parse_arguments():
    """Parse command-line arguments for power users."""
    parser = argparse.ArgumentParser(description="Certificate Authority Management Script")
    subparsers = parser.add_subparsers(dest='command')

    # Initialize CA
    init_parser = subparsers.add_parser('init', help='Initialize the Certificate Authority')
    init_parser.add_argument('--no-passphrase', action='store_true', help='Do not protect the CA private key with a passphrase')

    # Create Certificate
    create_parser = subparsers.add_parser('create', help='Create a new certificate')
    create_parser.add_argument('--type', choices=['server', 'client'], required=True, help='Type of certificate')
    create_parser.add_argument('--common-name', required=True, help='Common Name for the certificate')
    create_parser.add_argument('--validity-days', type=int, default=DEFAULT_VALIDITY_DAYS, help='Validity period in days')

    # Revoke Certificate
    revoke_parser = subparsers.add_parser('revoke', help='Revoke a certificate')
    revoke_parser.add_argument('--serial', required=True, help='Serial number of the certificate to revoke')

    args = parser.parse_args()
    return args

def main():
    """Main function."""
    check_dependencies()
    generate_openssl_conf()

    # This logic has been simplified from your original file for clarity and robustness
    if not is_ca_initialized():
        print("No existing Certificate Authority found.")
        choice = input("Would you like to initialize your first CA? (yes/no): ").strip().lower()
        if choice in ['yes', 'y']:
            initialize_ca()
        else:
            logging.info("CA initialization skipped. Exiting.")
            sys.exit(0)

    # After initialization check, proceed based on arguments or menu
    args = parse_arguments()
    if not args.command:
        main_menu()
        return

    # --- CLI Argument Handling ---
    if args.command == 'init':
        logging.info("CA is already initialized. If you want to start over, please remove the 'ca' directory.")

    elif args.command == 'create':
        cert_type = args.type
        common_name = args.common_name
        validity_days = args.validity_days

        if validity_days <= 0:
            logging.error("Validity period must be a positive integer.")
            sys.exit(1)

        extensions = 'server_cert' if cert_type == 'server' else 'usr_cert'
        subject = f"/CN={common_name}"
        # --- MODIFIED EXTENSIONS ---
        key_file = os.path.join(CERTS_DIR, f"{common_name}.key")
        csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr")
        cert_file = os.path.join(CERTS_DIR, f"{common_name}.crt")
        # --- END MODIFICATION ---

        for file in [key_file, csr_file, cert_file]:
            if os.path.exists(file):
                logging.warning(f"File {file} already exists and will be overwritten.")
                os.remove(file)

        subprocess.run(['openssl', 'genrsa', '-out', key_file, '2048'])
        os.chmod(key_file, 0o600)
        subprocess.run(['openssl', 'req', '-config', OPENSSL_CONF, '-key', key_file, '-new', '-out', csr_file, '-subj', subject])

        ca_passphrase_cli = getpass.getpass("Enter CA private key passphrase to sign the certificate: ")
        subprocess.run([
            'openssl', 'ca', '-config', OPENSSL_CONF, '-batch', '-extensions', extensions,
            '-days', str(validity_days), '-notext', '-md', 'sha256', '-in', csr_file, '-out', cert_file,
            '-passin', f'pass:{ca_passphrase_cli}'
        ])
        os.chmod(cert_file, 0o644)

        db = load_database()
        serial_number = get_certificate_serial(cert_file)
        db[serial_number] = {
            'common_name': common_name,
            'type': cert_type,
            'issued': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(days=validity_days)).isoformat(),
            'revoked': False,
            # --- MODIFIED EXTENSIONS ---
            'key_file': os.path.relpath(key_file, BASE_DIR),
            'cert_file': os.path.relpath(cert_file, BASE_DIR),
            # --- END MODIFICATION ---
        }
        save_database(db)
        logging.info(f"{cert_type.capitalize()} certificate for {common_name} created successfully via CLI.")

    elif args.command == 'revoke':
        serial = args.serial
        db = load_database()
        if serial in db and not db[serial]['revoked']:
            ca_passphrase_revoke_cli = getpass.getpass("Enter CA private key passphrase to revoke the certificate: ")
            cert_file = os.path.join(BASE_DIR, db[serial]['cert_file'])
            result = subprocess.run([
                'openssl', 'ca', '-config', OPENSSL_CONF, '-revoke', cert_file,
                '-passin', f'pass:{ca_passphrase_revoke_cli}'
            ], stderr=subprocess.PIPE)

            if result.returncode != 0:
                logging.error(result.stderr.decode())
                return

            db[serial]['revoked'] = True
            save_database(db)

            key_file = os.path.join(BASE_DIR, db[serial]['key_file'])
            cert_common_name = db[serial]['common_name']
            for file_path in [key_file, cert_file]:
                if os.path.exists(file_path):
                    shutil.move(file_path, os.path.join(REVOKED_CERTS_DIR, os.path.basename(file_path)))

            # --- MODIFIED EXTENSION ---
            csr_file = os.path.join(CERTS_DIR, f"{cert_common_name}.csr")
            # --- END MODIFICATION ---
            if os.path.exists(csr_file):
                shutil.move(csr_file, os.path.join(REVOKED_CERTS_DIR, os.path.basename(csr_file)))

            logging.info("Updating CRL...")
            update_crl(ca_passphrase_revoke_cli)
            logging.info(f"Certificate with serial {serial} revoked successfully via CLI.")
        else:
            logging.error("Invalid serial number or certificate already revoked.")

if __name__ == '__main__':
    main()
