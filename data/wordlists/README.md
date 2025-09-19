# CloudUnflare Enhanced - Wordlists Directory

This directory contains wordlists and dictionaries used by CloudUnflare Enhanced for various reconnaissance operations.

## Directory Structure

```
wordlists/
├── subdomains.txt          # Basic subdomain wordlist
├── dns_subdomains.txt      # Enhanced DNS enumeration wordlist
├── user-agents.txt         # User agent strings for rotation
├── common-ports.txt        # Common port list for scanning
├── service-names.txt       # Service detection wordlist
└── custom/                 # Custom wordlists directory
```

## Wordlist Sources

- **subdomains.txt**: Basic subdomain enumeration (copied from project root)
- **dns_subdomains.txt**: Enhanced DNS-specific subdomain list
- **user-agents.txt**: Realistic browser user agent strings
- **common-ports.txt**: Common TCP/UDP ports for reconnaissance
- **service-names.txt**: Service and application identifiers

## Usage

These wordlists are automatically mounted into the Docker container and used by various CloudUnflare modules:

- DNS enumeration modules use subdomain wordlists
- HTTP modules rotate through user agent strings
- Port scanning uses the common ports list
- Service detection uses service identification patterns

## Custom Wordlists

Add custom wordlists to the `custom/` subdirectory. They will be available to the application at runtime.

## Security Note

Wordlists should not contain sensitive information or be used for unauthorized reconnaissance activities.