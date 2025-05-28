import email
from email.policy import default
from bs4 import BeautifulSoup
import re
from llama_cpp import Llama
import os
import json
from datasets import Dataset
from transformers import pipeline
from tqdm import tqdm

pipe = pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")

# Internally built model to test emails to determine if they are phishing or not
# llm = Llama(model_path="phishingmodel.gguf", chat_format="chatml",n_gpu_layers=28,max_tokens=None,context_size=512)


def list_eml_files(directory):
    """
    Lists all files in the given directory that end with .eml.
    Returns a list of file names wih full path.
    """
    return [directory + "\\" + f for f in os.listdir(directory) if f.lower().endswith('.eml') and os.path.isfile(os.path.join(directory, f))]
def remove_html_tags(text):
    """Removes HTML tags from a string and replaces newlines and carriage returns with spaces."""
    # First remove HTML tags using BeautifulSoup
    clean_text = BeautifulSoup(text, "html.parser").get_text()
    # Replace all newlines and carriage returns with spaces
    clean_text = clean_text.replace('\n', ' ').replace('\r', ' ')
    # Replace multiple spaces with a single space
    clean_text = re.sub(r'\s+', ' ', clean_text)
    return clean_text.strip()

def remove_x_headers(email_content: str) -> str:
    """
    Parses an email string, removes all 'X-' header fields,
    and returns the modified email as a string.
    """
    msg = email.message_from_string(email_content, policy=default)
    headers_to_remove = [key for key in msg.keys() if key.lower().startswith('x-')]
    for key in headers_to_remove:
        del msg[key]
    return msg.as_string()

def unfold_headers(email_content: str) -> str:
    """
    Properly unfolds email headers according to RFC 5322.
    Handles MIME-encoded headers and complex folding cases.
    """
    lines = email_content.splitlines()
    unfolded_lines = []
    current_line = ""
    
    for line in lines:
        # Skip empty lines
        if not line.strip():
            if current_line:
                unfolded_lines.append(current_line)
                current_line = ""
            unfolded_lines.append("")
            continue
            
        # Check if this is a continuation line
        if line.startswith((' ', '\t', '=?')) and current_line:
            # For MIME-encoded headers, we need to be careful about the spacing
            if line.startswith('=?'):
                # If it's a new MIME-encoded part, add a space
                current_line += ' ' + line.lstrip()
            else:
                # For regular continuation, just remove leading whitespace
                current_line += line.lstrip()
        else:
            # If we have a current line, save it
            if current_line:
                unfolded_lines.append(current_line)
            # Start a new line
            current_line = line
    
    # Don't forget the last line
    if current_line:
        unfolded_lines.append(current_line)
    
    # Join lines with proper line endings and ensure proper spacing for MIME-encoded parts
    result = '\r\n'.join(unfolded_lines)
    
    # Clean up any double spaces that might have been introduced
    result = re.sub(r'\s+', ' ', result)
    
    # Ensure proper spacing around MIME-encoded parts
    result = re.sub(r'(=\?[^?]+\?[BQ]\?[^?]*\?=)\s*(=\?)', r'\1 \2', result)
    
    return result

def get_email_body_from_string(raw_email_string: str):
    """
    Parses an email string, extracts objects,
    and ensures X-headers are removed from the full email *before* extraction.
    """
    # First, clean the *entire raw email string* by removing X-headers
    cleaned_email_string = remove_x_headers(raw_email_string)

    # Now, parse the *cleaned* email string into a Message object
    msg = email.message_from_string(cleaned_email_string, policy=default)

    # Lets pull the parts we need from the email
    subject = msg['Subject'] if 'Subject' in msg else 'No Subject'
    sender = msg['From'] if 'From' in msg else 'No Sender'
    return_path = msg['Return-Path'] if 'Return-Path' in msg else 'No Return-Path'
    body = ""

    # Helper function to decode email part payload with fallback encodings
    def decode_payload(part):
        """Helper function to decode email part payload with fallback encodings"""
        try:
            charset = part.get_content_charset() or 'utf-8'
            # Handle special case for ISO-2022-JP
            if charset.lower() in ['iso-2022-jp', '_iso-2022-jp$esc']:
                charset = 'iso-2022-jp'
            return part.get_payload(decode=True).decode(charset, errors='replace')
        except Exception as e:
            # Try fallback encodings if the specified encoding fails
            fallback_encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            for encoding in fallback_encodings:
                try:
                    return part.get_payload(decode=True).decode(encoding, errors='replace')
                except:
                    continue
            return "--- Content Decoding Error ---"

    # If the email is multipart, we need to decode the payload of each part
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = part.get('Content-Disposition')
            # If the part is a text/plain and not an attachment, we can decode the payload
            if ctype == 'text/plain' and (cdisp is None or not cdisp.startswith('attachment')):
                try:
                    body = decode_payload(part)
                    break
                except Exception as e:
                    print(f"Warning: Could not decode part: {e}")
                    body = "--- Content Decoding Error ---"
    else:
        try:
            # If the email is not multipart, we can just decode the main payload
            body = decode_payload(msg)
        except Exception as e:
            print(f"Warning: Could not decode main payload: {e}")
            body = "--- Content Decoding Error ---"
    
    # Clean the email body from html tags to save tokens
    body = remove_html_tags(body)
    return subject, body, sender, return_path


def truncate_text(text, max_length=500):
    """
    Truncates text to a maximum length while trying to preserve complete words.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length].rsplit(' ', 1)[0]

# Read the raw email string from file and process
finaljsondata = []
#directory = "C:\\Users\\danfe\\OneDrive\\Desktop\\TestHugging\\phishing_pot\\email"
emails = list_eml_files("C:\\Users\\danfe\\OneDrive\\Desktop\\TestHugging\\phishing_pot\\email")

# Prepare data for batch processing
email_data = []

# Process each email with a pretty progress bar
for e in tqdm(emails[1:100], desc="Preprocessing emails"):
    try:
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        raw_email_string = None
        
        for encoding in encodings:
            try:
                #with open(directory + "\\" + e, "r", encoding=encoding) as f:
                with open(e, "r", encoding=encoding) as f:
                    raw_email_string = f.read()
                break  # If successful, break the encoding loop
            except UnicodeDecodeError:
                continue
        
        if raw_email_string is None:
            print(f"Warning: Could not decode file {e} with any of the attempted encodings")
            continue
        
        # Unfold headers before processing
        raw_email_string = unfold_headers(raw_email_string)
            
        subject, body, sender, return_path = get_email_body_from_string(raw_email_string)
        # Truncate the body text to fit within model's constraints
        truncated_body = truncate_text(body)
        
        email_data.append({
            'filename': e,
            'text': truncated_body,
            'subject': subject,
            'sender': sender,
            'return_path': return_path
        })
    except Exception as ex:
        print(f"Error processing file {e}: {str(ex)}")
        continue

# Create dataset
finalresults = []
for i in email_data[1:100]:
    results = pipe(i['text'])
    results.append({'filename': i['filename']})
    finalresults.append(results)

with open("phishing_results_bert.json", "w") as f:
     json.dump(finalresults, f, indent=4)
