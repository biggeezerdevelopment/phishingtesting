import email
import re
import os
import json
#import random
from llama_cpp import Llama
from email.policy import default
from bs4 import BeautifulSoup


llm = Llama(model_path="phishingmodel.gguf", chat_format="chatml",n_gpu_layers=28,max_tokens=500,context_size=4000)

prompt = "You are a cybersecurity expert specialized in detecting and analyzing phishing emails. who outputs in proper json format\n"
prompt += "Analyze the provided Body, Subject, Sender, and Return-Path\n"
prompt += "to determine whether it is a Malicious/Suspicious/Benign email.\n"
prompt += "If the percentage is above 0.49, it is a malicious email.\n"
prompt += "If the percentage is between 0.3 and 0.49, it is a suspicious email.\n"
prompt += "If the percentage is below 0.3, it is a benign email.\n"
prompt += "Output format:\n"
prompt += "Classification: either Malicious or Suspicious or Benign\n"
prompt += "percentage: 0.0-1.0\n"
prompt += "explanation: 10 words max\n"
prompt += "reasons: 3 reasons, 2 words each\n"

resp_format = {
                "type": "json_object",
                "json_schema": {
                    "name": "phishing_result",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "classification": {"type": "string"},
                            "percentage": {"type": "string"},
                            "explanation": {"type": "string"},
                            "reasons": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["classification", "percentage", "explanation", "reasons"]
                    }
                }
            }

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
    Parses an email string, extracts subject and body,
    and ensures X-headers are removed from the full email *before* extraction.
    """
    # First, clean the *entire raw email string* by removing X-headers
    #cleaned_email_string = remove_x_headers(raw_email_string)

    # Now, parse the *cleaned* email string into a Message object
    msg = email.message_from_string(raw_email_string, policy=default)

    subject = msg['Subject'] if 'Subject' in msg else 'No Subject'
   
    sender = msg['From'] if 'From' in msg else 'No Sender'
 
    return_path = msg['Return-Path'] if 'Return-Path' in msg else 'No Return-Path'
    body = ""
    
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

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = part.get('Content-Disposition')
            if ctype == 'text/plain' and (cdisp is None or not cdisp.startswith('attachment')):
                try:
                    body = decode_payload(part)
                    break
                except Exception as e:
                    print(f"Warning: Could not decode part: {e}")
                    body = "--- Content Decoding Error ---"
    else:
        try:
            body = decode_payload(msg)
        except Exception as e:
            print(f"Warning: Could not decode main payload: {e}")
            body = "--- Content Decoding Error ---"
    
    # Clean the email body from html tags to save tokens
    body = remove_html_tags(body)
    return subject, body, sender, return_path

def truncate_text(text, max_length=1000):
    """
    Truncates text to a maximum length while trying to preserve complete words.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length].rsplit(' ', 1)[0]


def process_email(e):
    try:
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        raw_email_string = None
        
        for encoding in encodings:
            try:
                #with open(directory + "\\" + e, "r", encoding=encoding) as f:
                with open(e, "r", encoding=encoding) as f:
                    raw_email_string = f.read()
                    #print(raw_email_string)
                break  # If successful, break the encoding loop
            except UnicodeDecodeError:
                continue
        
        if raw_email_string is None:
            print(f"Warning: Could not decode file {e} with any of the attempted encodings")
            
        # Unfold headers before processing
        #raw_email_string = unfold_headers(raw_email_string)
        subject, body, sender, return_path = get_email_body_from_string(raw_email_string)
        # Truncate the body text to fit within model's constraints
        truncated_body = truncate_text(body)
        
        email_data = {
            'filename': e,
            'text': truncated_body,
            'subject': subject,
            'sender': sender,
            'return_path': return_path
        }
        return email_data
    except Exception as ex:
        print(f"Error processing file {e}: {str(ex)}")
        

# Process the email with the LLM
def process_llm(examples):
    # This is the internal model I built to test emails to determine if they are phishing or not
    results = llm.create_chat_completion(
      messages = [
          {"role": "system", "content": prompt},  
          {"role": "user", "content": f"Body: {examples['text'][:300]} Subject: {examples['subject']} Sender: {examples['sender']} Return-Path: {examples['return_path']}"}
      ],
      response_format = resp_format    
    )
    #results = pipe(examples['text'], batch_size=8)
    return results['choices'][0]['message']['content']

# Debug: Print the first prediction to see its structure
#directory = "C:\\Users\\danfe\\OneDrive\\Desktop\\TestHugging\\phishing_pot\\email"
emails = list_eml_files("C:\\Users\\danfe\\OneDrive\\Desktop\\TestHugging\\phishing_pot\\email")
# pick a random email from the list
#random_email = random.choice(emails)
#print(random_email)
finaljsondata = []
for newemail in emails[0:100]:
    email_data = process_email(newemail)
    data = json.loads(process_llm(email_data))
    data.update({'filename': email_data['filename']})
    finaljsondata.append(data)

#print(f"\nTotal benign emails: {count}")
#print(f"\nTotal emails: {len(emails)}")
#print(f"\nPercentage of benign emails: {count/len(emails):.2%}")

# Optionally save results
# results = processed_dataset.to_dict()
with open("phishing_results_gguf.json", "w") as f:
    json.dump(finaljsondata, f, indent=4)
