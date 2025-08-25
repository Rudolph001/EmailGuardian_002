# Overview

Email Guardian is a web-based security application for managing and analyzing email traffic events. The system focuses on monitoring internal-to-external email communications, providing CSV data ingestion, rule-based filtering, whitelist management, keyword detection, and machine learning-based risk scoring. Built with Flask and SQLite, it's designed to handle large datasets (10,000+ events) with efficient batch processing and provides a comprehensive dashboard for security analysts to review, categorize, and manage email security events.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Web Framework
- **Flask** as the primary web framework with Jinja2 templating
- **Bootstrap with dark theme** for responsive UI components
- Modular route structure separating concerns across different functional areas

## Database Layer
- **SQLite** database with normalized schema design
- Core `events` table with foreign key relationships to `recipients`, `attachments`, and `policies` tables
- Additional tables for rules management (`rules`), whitelisting (`whitelist_domains`, `whitelist_emails`), and keyword lists (`keywords`)
- Database initialization handled through `models.py` with DDL schema definitions

## Data Processing Pipeline
- **CSV ingestion system** with streaming processing for large files
- Batch insertion (1000 rows per transaction) for performance optimization
- Multi-value field parsing for recipients, attachments, and policies using configurable delimiters
- Email normalization and validation using the `email_validator` library
- Internal vs external email classification based on configurable domain lists

## Rules Engine
- Priority-based rule system with actions: allow, block, escalate, flag
- Pattern matching for sender addresses, recipient domains, policy names, and keywords
- Whitelist management for trusted domains and email addresses
- Keyword detection with support for both literal strings and regular expressions

## Machine Learning Components
- **Scikit-learn** based risk scoring with Logistic Regression
- Feature extraction from event metadata (recipient count, attachment count, subject analysis)
- Heuristic fallback scoring when training data is insufficient
- Model versioning and batch re-scoring capabilities

## Configuration Management
- Centralized configuration in `config.py` with environment variable support
- Configurable internal domain lists for classification logic
- Adjustable batch sizes and processing limits for performance tuning

## Security Features
- Session management with configurable secret keys
- Input validation and sanitization for all user inputs
- SQL injection prevention through parameterized queries
- File upload restrictions and secure filename handling

# External Dependencies

## Python Libraries
- **Flask** - Web framework and request handling
- **SQLite3** - Database operations (built-in Python library)
- **Scikit-learn** - Machine learning models and feature processing
- **email-validator** - Email address validation and normalization
- **Werkzeug** - Secure file upload handling
- **tqdm** - Progress bars for data processing operations

## Frontend Dependencies
- **Bootstrap CSS Framework** - UI components and responsive design
- **Font Awesome** - Icon library for user interface elements
- **Replit Bootstrap Dark Theme** - Specialized dark theme styling

## Development Tools
- **Python logging** - Application monitoring and debugging
- **CSV module** - Data file processing and parsing

## File System Dependencies
- Local SQLite database file storage
- Temporary file handling for CSV uploads
- Static asset serving for CSS and client-side resources