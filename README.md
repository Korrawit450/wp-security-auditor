# WordPress Security & Misconfiguration Auditor

A lightweight, non-intrusive Python tool designed to perform rapid reconnaissance and identify critical security misconfigurations on WordPress websites.

## Key Features
- **Version Detection:** Identifies exposed core versions in meta tags and publicly accessible `readme.html` files.
- **User Enumeration Check:** Assesses whether the WordPress REST API (`/wp-json/wp/v2/users`) reveals valid administrative usernames.
- **Sensitive Endpoint Audit:** Checks the accessibility of `xmlrpc.php`, exposed backup configurations (`wp-config.php.bak`), and `.env` files.

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/wp-security-auditor.git
   cd wp-security-auditor