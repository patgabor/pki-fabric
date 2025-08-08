# pki-fabric
PKI Framework System

[![.NET](https://github.com/patgabor/pki-fabric/actions/workflows/dotnet.yml/badge.svg)](https://github.com/patgabor/pki-fabric/actions/workflows/dotnet.yml)

## Overview

pki-fabric is a comprehensive Public Key Infrastructure (PKI) framework designed to simplify the management, parsing, and handling of cryptographic data and certificates in .NET applications. It provides a set of robust utilities and types for working with:

- PEM-encoded cryptographic objects such as certificates, private keys, and certificate signing requests (CSRs)
- Detailed management of Subject Alternative Name (SAN) extensions including DNS names, IP addresses, RFC 822 emails, URIs, and more
- Parsing and validation of various X.509 certificate components with support for multiple SAN types
- Integration-ready design for building secure certificate-based authentication and encryption workflows

## Features

- Reliable parsing and serialization of PEM cryptographic materials
- Support for a broad range of SAN types to handle diverse certificate use cases
- Extensible design utilizing immutable types and .NET idioms for safety and clarity
- Suitable for both server-side and client-side certification operations in enterprise-grade security systems

## Usage

The framework is intended to be used as a foundation or utility library in applications that require strong PKI capabilities, such as:

- Automated certificate issuance and renewal systems
- Secure communication platforms requiring certificate validation
- Custom identity management and access control solutions

---

For more information and detailed documentation, please refer to the project wiki or README sections.
