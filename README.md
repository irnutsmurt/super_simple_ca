# Super Simple CA - Certificate Authority Management Script

`super_simple_ca.py` is a Python script designed to simplify the process of managing a Certificate Authority (CA). It provides an easy-to-use interface for initializing a CA, creating certificates, revoking certificates, and how to install the root certificate on your system. The script supports both interactive menu-driven usage and command-line operations for power users.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Command-Line Mode](#command-line-mode)
    - [Initialize CA](#initialize-ca)
    - [Create Certificate](#create-certificate)
    - [Revoke Certificate](#revoke-certificate)
- [Script Behavior](#script-behavior)
  - [OpenSSL Dependency Check](#openssl-dependency-check)
- [Examples](#examples)
- [License](#license)

## Features

- **Initialize a Certificate Authority**: Set up a new CA with custom configurations.
- **Create Certificates**: Generate server or client certificates with support for Subject Alternative Names (SANs).
- **Revoke Certificates**: Revoke existing certificates and update the Certificate Revocation List (CRL).
- **Install Root Certificate**: Guidance on installing the root CA certificate on various operating systems.
- **Interactive and Command-Line Modes**: Use the script interactively or automate tasks via command-line arguments.
- **Logging**: All operations are logged for auditing purposes.
- **Dependency Check**: The script checks for the presence of OpenSSL and assists with installation if not found.

## Prerequisites

- **Python 3.6 or higher**
- **OpenSSL**: Ensure OpenSSL is installed and accessible from the command line.
- **Required Python Libraries**: `argparse`, `subprocess`, `logging`, `json`, `shutil`, `platform`, `datetime`, `getpass`

## Installation

1. **Clone the Repository or Download the Script**:
   ```bash
   git clone https://github.com/irnutsmurt/super_simple_ca.git
   ```
   Or download `super_simple_ca.py` directly.

2. **Make the Script Executable**:
   ```bash
   chmod +x super_simple_ca.py
   ```

3. **Install Required Python Libraries** (if not already installed):
   ```bash
   pip install argparse subprocess logging json shutil platform datetime getpass
   ```

4. **Ensure OpenSSL is Installed**:
   - **Linux**:
     ```bash
     sudo apt-get install openssl
     ```
   - **macOS**:
     ```bash
     brew install openssl
     ```
   - **Windows**:
     Download and install from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html).

## Usage

`super_simple_ca.py` can be used in two ways:

1. **Interactive Mode**: Run the script without arguments to use the menu-driven interface.
2. **Command-Line Mode**: Use arguments to perform actions directly from the command line.

### Interactive Mode

Simply run the script without any arguments:

```bash
./super_simple_ca.py
```

You will be presented with a menu:

```
Certificate Authority Management
1. Initialize CA
2. Create Certificate
3. Revoke Certificate
4. Install Root Certificate
5. Exit
Enter your choice (1-5):
```

Follow the prompts to perform desired actions.

### Command-Line Mode

For automation or advanced usage, use the following command-line arguments:

```bash
./super_simple_ca.py [command] [options]
```

#### Available Commands

- `init`: Initialize the Certificate Authority.
- `create`: Create a new certificate.
- `revoke`: Revoke an existing certificate.

#### Initialize CA

Initialize the Certificate Authority. You can choose to protect the CA's private key with a passphrase or not.

```bash
./super_simple_ca.py init [--no-passphrase]
```

**Options**:

- `--no-passphrase`: Do not protect the CA private key with a passphrase.

**Example**:

```bash
./super_simple_ca.py init
```

This will start the CA initialization process and prompt you for configuration details.

#### Create Certificate

Create a new server or client certificate.

```bash
./super_simple_ca.py create --type TYPE --common-name CN [--validity-days DAYS]
```

**Options**:

- `--type`: Type of certificate (`server` or `client`). **Required**.
- `--common-name`: Common Name for the certificate (e.g., domain name, user name). **Required**.
- `--validity-days`: Validity period in days (default: 825 days).

**Example**:

```bash
./super_simple_ca.py create --type server --common-name www.example.com --validity-days 365
```

This command creates a server certificate for `www.example.com` valid for 365 days.

#### Revoke Certificate

Revoke an existing certificate by its serial number.

```bash
./super_simple_ca.py revoke --serial SERIAL_NUMBER
```

**Options**:

- `--serial`: Serial number of the certificate to revoke. **Required**.

**Example**:

```bash
./super_simple_ca.py revoke --serial 1002
```

This command revokes the certificate with serial number `1002`.

## Script Behavior

### OpenSSL Dependency Check

Before performing any operations, the script checks if OpenSSL is installed on your system:

- **If OpenSSL is Found**: The script proceeds with the requested operations.
- **If OpenSSL is Not Found**:
  - The script informs you that OpenSSL is not installed.
  - Provides guidance on installing OpenSSL based on your operating system.
  - Offers to install OpenSSL automatically if you're on Linux or macOS (requires administrative privileges).
  - On Windows, directs you to download OpenSSL from the official website.

**Example Output When OpenSSL is Missing**:

```
ERROR - OpenSSL is not installed.
OpenSSL is not installed. Would you like to install it now? (yes/no):
```

**Note**: The script requires OpenSSL to function properly, as it leverages OpenSSL commands for cryptographic operations.

## Examples

### Initialize the CA with a Passphrase

```bash
./super_simple_ca.py init
```

Follow the prompts to enter details and set a passphrase.

### Initialize the CA Without a Passphrase

```bash
./super_simple_ca.py init --no-passphrase
```

### Create a Server Certificate via Command Line

```bash
./super_simple_ca.py create --type server --common-name myserver.com --validity-days 730
```

### Revoke a Certificate via Command Line

```bash
./super_simple_ca.py revoke --serial 1003
```

### Use the Interactive Menu

```bash
./super_simple_ca.py
```

Select options from the menu to perform tasks.

## License

This project is licensed under the MIT License.

---

*For any issues or contributions, please open an issue or submit a pull request on the project's GitHub repository.*
