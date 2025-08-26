import os

# Database configuration
DATABASE_PATH = "email_guardian.sqlite"

# Session secret key
SECRET_KEY = "your-secret-key-change-this-in-production"

# Internal domains for classification
INTERNAL_DOMAINS = {
    "company.com",
    "internal.com",
    "corp.com"
}

# CSV processing configuration
BATCH_SIZE = 500
MAX_SPLITS = 50
DELIMITERS = ["|", ",", ";", "\n", "\r\n"]

# ML Model configuration
ML_MODEL_VERSION = "v1"

# File upload limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Logging configuration
LOG_LEVEL = "INFO"