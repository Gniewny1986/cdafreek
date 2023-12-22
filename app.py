import sys
import asyncio
from os import path

import requests
import hashlib
import hmac
import base64
from urllib.parse import urlparse, quote
from flask import Flask, request, jsonify
import datetime
import gunicorn
import json

app = Flask(__name__)

# Define cda_username and cda_password as global variables
cda_username = None
cda_password = None
current_account_index = 0

# Load accounts from konta.txt file
account_file = "konta.txt"
accounts = []
with open(account_file, "r") as file:
    for line in file:
        parts = line.strip().split(":")
        if len(parts) == 2:
            accounts.append({"username": parts[0], "password": parts[1]})


# Function to update global cda_username and cda_password variables
def update_credentials():
    global cda_username, cda_password, current_account_index
    if current_account_index < len(accounts):
        account = accounts[current_account_index]
        cda_username = account["username"]
        cda_password = account["password"]
        current_account_index += 1
    else:
        print("All accounts from konta.txt have been used.")
        sys.exit(1)


# Initialize the credentials
update_credentials()

# Initialize the Discord client

cache_file = "oauth.json"


# Function to get the bearer token
def get_bearer_token(username, password):
    if path.exists(cache_file):
        with open(cache_file, "r") as infile:
            file_data = json.load(infile)

            if username in file_data:
                access_token = file_data[username]

                if int(datetime.datetime.now().timestamp()) < access_token['expiration_date']:
                    return access_token
    else:
        file_data = {}

    headers = {
        'Accept': 'application/vnd.cda.public+json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.147 Safari/537.36',
        'Authorization': 'Basic YzU3YzBlZDUtYTIzOC00MWQwLWI2NjQtNmZmMWMxY2Y2YzVlOklBTm95QlhRRVR6U09MV1hnV3MwMW0xT2VyNWJNZzV4clRNTXhpNGZJUGVGZ0lWUlo5UGVYTDhtUGZaR1U1U3Q',
    }

    pwd_md5 = ""
    for byte in hashlib.md5(password.encode('utf-8')).digest():
        hexik = bytes((byte & 255,)).hex()
        while len(hexik) < 2:
            hexik = "0" + hexik
        pwd_md5 += hexik
    digest = hmac.new(
        's01m1Oer5IANoyBXQETzSOLWXgWs01m1Oer5bMg5xrTMMxRZ9Pi4fIPeFgIVRZ9PeXL8mPfXQETZGUAN5StRZ9P'.encode(
            'utf-8'),
        pwd_md5.encode('utf-8'), hashlib.sha256).digest()
    password_hash = base64.urlsafe_b64encode(digest).decode('utf-8').replace('=', '')

    res = requests.post(
        f'https://api.cda.pl/oauth/token?grant_type=password&login={username}&password={password_hash}',
        headers=headers)

    data = res.json()

    now = datetime.datetime.now()
    expires_in = datetime.timedelta(seconds=data['expires_in'])
    expiration_time = now + expires_in

    data['expiration_date'] = int(expiration_time.timestamp())

    file_data[username] = data

    with open(cache_file, "w") as outfile:
        json.dump(file_data, outfile)
    return data


# Function to get video URLs for all qualities
def get_video_urls_all_qualities(video_url, bearer_token):
    headers = {
        'Accept': 'application/vnd.cda.public+json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.147 Safari/537.36',
        'Authorization': 'Basic YzU3YzBlZDUtYTIzOC00MWQwLWI2NjQtNmZmMWMxY2F2YzVlOklBTm95QlhRRVR6U09MV1hnV3MwMW0xT2VyNWJNZzV4clRNTXhpNGZJUGVGZ0lWUlo5UGVYTDhtUGZaR1U1U3Q'
    }
    headers.update(bearer_token)

    search_video_id = video_url.split('/')
    if search_video_id[-1].lower() == 'vfilm':
        video_id = search_video_id[-2]
    else:
        video_id = search_video_id[-1]

    res = requests.get('https://api.cda.pl' + '/video/' + video_id, headers=headers)
    video_json = res.json()['video']

    title = video_json['title']
    img = video_json.get('thumb_premium')

    if not img:
        img = video_json['thumb']

    urls = []
    qualities = video_json['qualities']
    for _i in range(len(qualities)):
        name = qualities[_i]['name']
        url = qualities[_i]['file']
        urls.append({
            'name': name,
            'url': url
        })

    return title, img, urls


# Function to validate URI
def uri_validator(x):
    try:
        result = urlparse(x)
        if ("cda.pl" in result.netloc or "cda.pl" in result.path) and "/video/" in result.path:
            return True, result.netloc + result.path
    except:
        pass
    return False, None


# Function to get URLs
def get_urls(url):
    result, valid_url = uri_validator(url)
    if not result:
        print("Not correct URL to video on cda")
        return
    bearer_token = {'Authorization': 'Bearer ' + str(get_bearer_token(cda_username, cda_password)['access_token'])}
    title, img, urls = get_video_urls_all_qualities(valid_url, bearer_token)
    print('\nTitle: ' + title)
    print('Img URL: ' + img)
    for x in urls:
        print('\t[' + x['name'] + ']' + x['url'])


# Define a list of allowed passwords
ALLOWED_PASSWORDS = ["Vehhty777!", "PirateSiteApiCDApass999!", "Trevcio123989!"]  # Add your allowed passwords here

# Define the log file path
LOG_FILE = "request_logs.txt"


# Function to log the request with timestamp, IP address, and password
def log_request(password, ip_address):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{current_time}: IP Address - {ip_address}, Password Used - {password}\n"
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)


def send_discord_webhook(date, password, url):
    webhook_url = 'https://discord.com/api/webhooks/1166370138250027018/5ugQGJ_bsLTw0srLliYdW_jdEmqmJdiIXo_9INH65j-YTm904b6_niHcR4DfcOCjLX6n'  # Replace with your actual Discord webhook URL

    # Create an embed for the Discord webhook
    embed = {
        'title': 'CDA API',
        'description': f'Użyte hasło: {password}\nURL: {url}',
        'color': 16711680  # Red color, you can change it to a different color
    }

    # Create a payload for the Discord webhook with the embed
    payload = {
        'embeds': [embed]
    }

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)
        if response.status_code == 204:
            print('Webhook message sent successfully.')
        else:
            print(f'Failed to send webhook message. Status code: {response.status_code}')
    except Exception as e:
        print(f'Error sending webhook message: {str(e)}')


@app.route('/cda', methods=['POST'])
def generate_link():
    try:
        # Check if the 'X-Api-Password' header is present in the request
        if 'X-Api-Password' not in request.headers:
            return jsonify({'error': 'Authentication required'}), 401  # Unauthorized

        # Get the provided password from the request headers
        provided_password = request.headers['X-Api-Password']

        # Check if the provided password is in the list of allowed passwords
        if provided_password not in ALLOWED_PASSWORDS:
            return jsonify({'error': 'Authentication failed'}), 401  # Unauthorized

        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({'error': 'URL not provided'}), 400

        # Get the client's IP address
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

        # Try to generate link with the current account
        try:
            # Use cda_username and cda_password in your functions
            bearer_token = {'Authorization': 'Bearer ' + str(get_bearer_token(cda_username, cda_password)['access_token'])}
            title, img, urls = get_video_urls_all_qualities(url, bearer_token)

            response_data = {
                'title': title,
                'img_url': img,
                'urls': [{'name': x['name'], 'url': x['url']} for x in urls]
            }

            # Log the successful request with IP address
            log_request(provided_password, client_ip)

            # Send Discord webhook message with the date and password
            current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            send_discord_webhook(current_date, provided_password, url)

            return jsonify(response_data)

        except Exception as e:
            # Log the error
            print(f"Error while generating link: {str(e)}")
            # Update credentials and try again with a different account
            update_credentials()
            # Retry with the next account
            return generate_link()

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(port=80)
