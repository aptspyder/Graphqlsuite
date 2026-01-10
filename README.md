# GraphQLSuite

**Advanced GraphQL Vulnerability Scanner & Exploit Generator**


GraphQLSuite is a high-performance, concurrent Go tool designed for professional bug bounty hunters and penetration testers.

**Key Feature: Live Exploit Generation.**
If a vulnerability is found, GraphQLSuite generates the exact `curl` command needed to reproduce the exploit instantly for your report.

## Features

- **20+ Automated Checks**: Covers OWASP vectors, DoS, CSRF, and Info Leaks.
- **Live Proofs**: Automatically generates `curl` POCs for verified findings.
- **Concurrency**: Blazing fast scanning using Go routines.
- **DoS Detection**: Distinguishes between "Config Weakness" (Medium) and "Confirmed Lag" (High).

## Installation


```
go install [github.com/aptspider/Graphqlsuite/v2@v2.1.5
````
## Usage 

```
Graphqlsuite -t https://example.com/nft-api/graphql 
````

## Disclaimer

This tool is strictly for educational purposes and authorized security research only. Any actions and/or activities related to the material contained within this repository are solely your responsibility. The developers will not be held responsible for any misuse or damage caused by this program. Do not use this tool on systems you do not have explicit permission to test.
