# Email Security Analysis Tools

This repository contains two Python utilities for email security analysis and processing:

1. Phishing Email Detection System
2. Email Processing Utility

## Phishing Email Detection System

A machine learning-based system that analyzes emails to detect potential phishing attempts using a GGUF model.

### Features
- Analyzes email content, subject, sender, and return path
- Classifies emails into three categories:
  - Malicious (score > 0.49)
  - Suspicious (score between 0.3 and 0.49)
  - Benign (score < 0.3)
- Provides detailed analysis including:
  - Classification result
  - Confidence percentage
  - Brief explanation
  - Key reasons for classification

### Requirements
- Python 3.x
- llama-cpp-python
- BeautifulSoup4
- email (standard library)

### Usage
```python
from phishingtest_gguf_model import process_email, process_llm

# Process an email file
email_data = process_email("path/to/email.eml")

# Analyze the email
result = process_llm(email_data)
```

## Email Processing Utility

A utility for processing and cleaning email files, particularly useful for preparing emails for analysis.

### Features
- Removes HTML tags from email content
- Handles multiple email encodings (UTF-8, Latin-1, CP1252, ISO-8859-1)
- Properly unfolds email headers according to RFC 5322
- Removes X-headers
- Extracts email components:
  - Subject
  - Body
  - Sender
  - Return-Path

### Key Functions
- `remove_html_tags()`: Cleans HTML content from email body
- `unfold_headers()`: Properly unfolds email headers
- `remove_x_headers()`: Removes X-header fields
- `get_email_body_from_string()`: Extracts email components
- `truncate_text()`: Truncates text while preserving word boundaries

### Usage
```python
from phishingtest_gguf_model import get_email_body_from_string

# Process raw email string
subject, body, sender, return_path = get_email_body_from_string(raw_email_string)
```

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install llama-cpp-python beautifulsoup4
```

## Model Requirements

The system uses a GGUF model file named `phishingmodel.gguf`. Make sure to:
1. Place the model file in the project directory
2. Ensure the model file is compatible with llama-cpp-python
3. Verify the model has been trained for phishing detection tasks

## Output Format

The system outputs results in JSON format:
```json
{
    "classification": "Malicious|Suspicious|Benign",
    "percentage": "0.0-1.0",
    "explanation": "Brief explanation",
    "reasons": ["reason1", "reason2", "reason3"]
}
```

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here] 