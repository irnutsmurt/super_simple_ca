#!/usr/bin/env python3
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

# Ensure necessary directories exist and have correct permissions
DIRECTORIES = [CA_DIR, CERTS_DIR, REVOKED_CERTS_DIR, CRL_DIR, LOGS_DIR, DB_DIR, CONFIGS_DIR]

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

[ policy_loose ]
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
ST  = California
L   = Bay Area
O   = My Company
OU  = IT Department
CN  = My Company CA

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
    state = input("Enter State or Province Name [California]: ") or "California"
    locality = input("Enter Locality Name [San Francisco]: ") or "San Francisco"
    organization = input("Enter Organization Name [My Company]: ") or "My Company"
    organizational_unit = input("Enter Organizational Unit Name [IT Department]: ") or "IT Department"
    common_name = input("Enter Common Name [My Company CA]: ") or "My Company CA"
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

def create_certificate():
    """Create a new certificate with Subject Alternative Name (SAN) support."""
    logging.info("Creating a new certificate...")
    print("\nCertificate Types:")
    print("1. Server Certificate (used to authenticate servers to clients) - Examples: Web Servers (HTTPS), VPN Servers, Email Servers, API Endpoints")
    print("2. Client Certificate (used to authenticate clients to servers) - Examples: User Authentication, VPN Clients, Secure APIs, Enterprise Applications")
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

    common_name = input("Enter Common Name (e.g., domain name or user name): ").strip()
    if not common_name:
        logging.error("Common Name cannot be empty.")
        return

    country = input("Enter Country Name (2 letter code) [US]: ") or "US"
    state = input("Enter State or Province Name [California]: ") or "California"
    locality = input("Enter Locality Name [San Francisco]: ") or "San Francisco"
    organization = input("Enter Organization Name [My Company]: ") or "My Company"
    organizational_unit = input("Enter Organizational Unit Name [IT Department]: ") or "IT Department"
    email = input("Enter Email Address [user@example.com]: ") or "user@example.com"

    # Prompt for validity period
    while True:
        validity_input = input(f"Enter certificate validity period in days [{DEFAULT_VALIDITY_DAYS}]: ").strip() or str(DEFAULT_VALIDITY_DAYS)
        try:
            validity_days = int(validity_input)
            if validity_days <= 0:
                raise ValueError
            break
        except ValueError:
            logging.error("Please enter a positive integer for the validity period.")
            continue

    # Prompt for SANs
    san_input = input("Enter Subject Alternative Names (SANs) separated by commas (e.g., DNS:www.example.com, IP:192.168.1.1): ").strip()
    san_list = san_input.split(',') if san_input else []

    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"

    key_file = os.path.join(CERTS_DIR, f"{common_name}.key.pem")
    csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr.pem")
    cert_file = os.path.join(CERTS_DIR, f"{common_name}.cert.pem")

    # Check if files already exist and handle accordingly
    existing_files = [key_file, csr_file, cert_file]
    for file in existing_files:
        if os.path.exists(file):
            logging.warning(f"File {file} already exists.")
            # Remove existing files to avoid permission errors
            os.remove(file)

    # Generate private key
    result = subprocess.run([
        'openssl', 'genrsa', '-out', key_file, '2048'
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return
    os.chmod(key_file, 0o600)  # Less restrictive permissions

    # Generate CSR with SAN support
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

    result = subprocess.run([
        'openssl', 'req', '-key', key_file, '-new', '-out', csr_file, '-config', san_file
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return

    # Sign the certificate
    ca_key = os.path.join(CA_DIR, 'ca.key.pem')
    ca_cert = os.path.join(CA_DIR, 'ca.cert.pem')

    result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-batch', '-extensions', extensions,
        '-days', str(validity_days), '-notext', '-md', 'sha256', '-in', csr_file, '-out', cert_file
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return
    os.chmod(cert_file, 0o644)  # Less restrictive permissions

    # Update database
    db = load_database()
    serial_number = get_certificate_serial(cert_file)
    db[serial_number] = {
        'common_name': common_name,
        'type': cert_type,
        'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=validity_days)).isoformat(),
        'revoked': False,
        'key_file': key_file,
        'cert_file': cert_file,
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
    db[serial_to_revoke]['revoked'] = True
    save_database(db)

    # Revoke the certificate using OpenSSL
    cert_file = db[serial_to_revoke]['cert_file']
    print("Please enter your CA passphrase to revoke the certificate.")
    result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-revoke', cert_file
    ], stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(result.stderr.decode())
        return

    # Move revoked certificate files to revokedcerts directory
    key_file = db[serial_to_revoke]['key_file']
    cert_common_name = db[serial_to_revoke]['common_name']
    files_to_move = [key_file, cert_file]
    for file_path in files_to_move:
        if os.path.exists(file_path):
            file_name = os.path.basename(file_path)
            new_path = os.path.join(REVOKED_CERTS_DIR, file_name)
            os.rename(file_path, new_path)
            logging.info(f"Moved {file_path} to {new_path}")
    # Remove CSR file if exists
    csr_file = os.path.join(CERTS_DIR, f"{cert_common_name}.csr.pem")
    if os.path.exists(csr_file):
        new_csr_path = os.path.join(REVOKED_CERTS_DIR, os.path.basename(csr_file))
        os.rename(csr_file, new_csr_path)
        logging.info(f"Moved {csr_file} to {new_csr_path}")

    # Update CRL
    logging.info("Updating CRL...")
    print("Please enter your CA passphrase to update the CRL.")
    update_crl()

    logging.info(f"Certificate with serial {serial_to_revoke} revoked successfully.")

def update_crl():
    """Update the Certificate Revocation List."""
    crl_file = os.path.join(CRL_DIR, 'crl.pem')

    result = subprocess.run([
        'openssl', 'ca', '-config', OPENSSL_CONF, '-gencrl', '-out', crl_file
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

def main_menu():
    """Display the main menu."""
    while True:
        print("\nCertificate Authority Management")
        print("1. Initialize CA")
        print("2. Create Certificate")
        print("3. Revoke Certificate")
        print("4. Install Root Certificate")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            initialize_ca()
        elif choice == '2':
            create_certificate()
        elif choice == '3':
            revoke_certificate()
        elif choice == '4':
            install_root_certificate()
        elif choice == '5':
            logging.info("Exiting the script.")
            sys.exit(0)
        else:
            logging.error("Invalid choice. Please enter a number between 1 and 5.")

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
    generate_openssl_conf()  # Generate OpenSSL configuration

    args = parse_arguments()

    # Check if CA is initialized
    if not is_ca_initialized():
        print("No existing Certificate Authority found.")
        choice = input("Would you like to initialize your first CA? (yes/no): ").strip().lower()
        if choice in ['yes', 'y']:
            initialize_ca()
        else:
            logging.info("Skipping CA initialization.")
            # Proceed to menu or exit based on user preference
            if args.command is None:
                main_menu()
            else:
                logging.error("CA must be initialized before performing this operation.")
                sys.exit(1)

    # If arguments are provided, use CLI mode
    if args.command:
        if args.command == 'init':
            # Initialize CA with or without passphrase
            initialize_ca()
        elif args.command == 'create':
            cert_type = args.type
            common_name = args.common_name
            validity_days = args.validity_days

            # Validate validity_days
            if validity_days <= 0:
                logging.error("Validity period must be a positive integer.")
                sys.exit(1)

            extensions = 'server_cert' if cert_type == 'server' else 'usr_cert'
            subject = f"/CN={common_name}"
            key_file = os.path.join(CERTS_DIR, f"{common_name}.key.pem")
            csr_file = os.path.join(CERTS_DIR, f"{common_name}.csr.pem")
            cert_file = os.path.join(CERTS_DIR, f"{common_name}.cert.pem")

            # Check if files already exist and handle accordingly
            existing_files = [key_file, csr_file, cert_file]
            for file in existing_files:
                if os.path.exists(file):
                    logging.warning(f"File {file} already exists.")
                    os.remove(file)

            # Generate private key
            subprocess.run([
                'openssl', 'genrsa', '-out', key_file, '2048'
            ])
            os.chmod(key_file, 0o600)

            # Generate CSR
            subprocess.run([
                'openssl', 'req', '-config', OPENSSL_CONF, '-key', key_file, '-new', '-out', csr_file, '-subj', subject
            ])

            # Sign the certificate
            subprocess.run([
                'openssl', 'ca', '-config', OPENSSL_CONF, '-batch', '-extensions', extensions,
                '-days', str(validity_days), '-notext', '-md', 'sha256', '-in', csr_file, '-out', cert_file
            ])
            os.chmod(cert_file, 0o644)

            # Update database
            db = load_database()
            serial_number = get_certificate_serial(cert_file)
            db[serial_number] = {
                'common_name': common_name,
                'type': cert_type,
                'issued': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(days=validity_days)).isoformat(),
                'revoked': False,
                'key_file': key_file,
                'cert_file': cert_file,
            }
            save_database(db)

            logging.info(f"{cert_type.capitalize()} certificate for {common_name} created successfully via CLI.")
        elif args.command == 'revoke':
            # Implement command-line certificate revocation
            serial = args.serial
            db = load_database()
            if serial in db and not db[serial]['revoked']:
                db[serial]['revoked'] = True
                save_database(db)
                # Revoke the certificate using OpenSSL
                cert_file = db[serial]['cert_file']
                print("Please enter your CA passphrase to revoke the certificate.")
                result = subprocess.run([
                    'openssl', 'ca', '-config', OPENSSL_CONF, '-revoke', cert_file
                ], stderr=subprocess.PIPE)
                if result.returncode != 0:
                    logging.error(result.stderr.decode())
                    return

                # Move revoked certificate files to revokedcerts directory
                key_file = db[serial]['key_file']
                cert_common_name = db[serial]['common_name']
                files_to_move = [key_file, cert_file]
                for file_path in files_to_move:
                    if os.path.exists(file_path):
                        file_name = os.path.basename(file_path)
                        new_path = os.path.join(REVOKED_CERTS_DIR, file_name)
                        os.rename(file_path, new_path)
                        logging.info(f"Moved {file_path} to {new_path}")
                # Remove CSR file if exists
                csr_file = os.path.join(CERTS_DIR, f"{cert_common_name}.csr.pem")
                if os.path.exists(csr_file):
                    new_csr_path = os.path.join(REVOKED_CERTS_DIR, os.path.basename(csr_file))
                    os.rename(csr_file, new_csr_path)
                    logging.info(f"Moved {csr_file} to {new_csr_path}")

                # Update CRL
                logging.info("Updating CRL...")
                print("Please enter your CA passphrase to update the CRL.")
                update_crl()
                logging.info(f"Certificate with serial {serial} revoked successfully via CLI.")
            else:
                logging.error("Invalid serial number or certificate already revoked.")
        else:
            logging.error("Unknown command.")
    else:
        # If no arguments are provided, show the main menu
        main_menu()

if __name__ == '__main__':
    main()
