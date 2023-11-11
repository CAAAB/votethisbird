import requests
import json
import time
from faker import Faker

import re
import quopri

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import os
import base64
import email

my_email_stump = os.environ.get('EMAIL')

# Initialize a Faker generator
fake = Faker()

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def first_post():
    # Generate fake first and last names
    first_name = fake.first_name()
    last_name = fake.last_name()

    # Generate email with current Unix timestamp
    timestamp = int(time.time())
    my_email = f"{my_email_stump}+{timestamp}@gmail.com"
    #print(f"Randomly generated email: {my_email}")  # Print the random email

    # Define the payload with the fake names and email
    payload = {
        "birds": [128],
        "name": first_name,
        "last_name": last_name,
        "email": my_email,
        "phone": None,
        "adult_contact": "No",
        "comments": None,
        "youth_contact": False,
        "donation": 0,
        "stripe_txid": None
    }

    # Set the headers
    headers = {
        "accept": "*/*",
        "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7,it;q=0.6",
        "content-type": "application/json",
        "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin"
    }

    # Send the POST request
    response = requests.post("https://www.birdoftheyear.org.nz/api/vote2", headers=headers, json=payload)

    # Check if the request was successful
    if response.status_code == 200:
        print("Vote submitted successfully.")
    else:
        print(f"Failed to submit vote. Status code: {response.status_code}")
    return my_email, response.status_code


def extract_code_and_token(email_content):
    # Decode quoted-printable content
    decoded_content = quopri.decodestring(email_content).decode('utf-8', errors='replace')

    # Regular expression to find the code after the specific phrase
    code_pattern = r'below, and enter this unique code:\s*\n*\s*([A-Z0-9]{4})'
    # Regular expression to find the URL and extract the token
    token_pattern = r'https?://[^\s]+token=([^\s=]+)'

    # Search for the code and token in the decoded content
    code_match = re.search(code_pattern, decoded_content)
    token_match = re.search(token_pattern, decoded_content)

    # Extract the code and token if found
    code = code_match.group(1) if code_match else None
    token = token_match.group(1) if token_match else None

    return code, token

def post_validation(code, token):
    url = "https://www.birdoftheyear.org.nz/api/validate"

    headers = {
        "accept": "*/*",
        "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7,it;q=0.6",
        "content-type": "application/json",
        "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin"
    }

    payload = {
        "code": code,
        "token": token
    }

    response = requests.post(url, headers=headers, json=payload)
    return response

def get_service():
    creds = None
    # The file token.json stores the user's access and refresh tokens.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    return service

def search_messages(service, query):
    result = service.users().messages().list(userId='me', q=query).execute()
    messages = []
    if 'messages' in result:
        messages.extend(result['messages'])
    return messages

def get_message(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    msg_str = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
    mime_msg = email.message_from_bytes(msg_str)
    return mime_msg

import os

def main():
    loop_count = 0

    while True:
        # Execute first POST request and get email and status code
        my_email, status_code_first_post = first_post()
        print(f"Loop {loop_count}: Email used: {my_email}, First POST status code: {status_code_first_post}")

        time.sleep(3)
        service = get_service()
        query = 'subject:Bird of the Century'
        messages = search_messages(service, query)

        final_status_code = "No messages found"
        if messages:
            # Get the latest email
            message = messages[0]
            msg_id = message['id']
            email_content = get_message(service, msg_id)
            code, token = extract_code_and_token(str(email_content))
            print(f"Extracted code: {code}, token: {token}")

            response = post_validation(code, token)
            final_status_code = response.status_code
            print(f"Validation POST status code: {final_status_code}")

        # Increment loop count
        loop_count += 1
if __name__ == '__main__':
    main()

