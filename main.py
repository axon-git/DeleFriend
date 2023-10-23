import yaml
import argparse
from google.auth.credentials import Credentials
from src.gcp_sa_enum import ServiceAccountEnumerator
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError
from src import oauth_scope_enumrator
import os
import time


parser = argparse.ArgumentParser(description="DeleFriend Tool")
parser.add_argument('-c', '--config', type=str, required=True, help="Path to the GCP IAM configuration file")
parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose/debugging mode")
args = parser.parse_args()
# load configuration
with open(args.config, 'r') as file:
    config = yaml.safe_load(file)

OAUTH_TOKEN = config.get('oauth_token')
USER_EMAIL = config.get('user_email')

SCOPES_FILE = 'src/oauth_scopes.txt'  #  scopes file
KEY_FOLDER = 'SA_private_keys'


class CustomCredentials(Credentials):

    def __init__(self, token):
        self.token = token

    def apply(self, headers):
        headers['Authorization'] = f'Bearer {self.token}'

    def before_request(self, request, method, url, headers):
        self.apply(headers)

    def refresh(self, request):
        pass


def results():
    timestamp = int(time.time())
    result_folder = 'results'
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)

    filename = f'results_{timestamp}.txt'
    filepath = os.path.join(result_folder, filename)
    print(f"\n\n[+] Saving results to results/{filename} ...")

    with open(filepath, 'w') as f:
        valid_results = oauth_scope_enumrator.get_valid_results()
        for json_path, valid_scopes in valid_results.items():
            if valid_scopes:
                f.write(f'Service Account Key Name: {os.path.basename(json_path)}\n')
                f.write('Valid OAuth Scopes:\n')
                for scope in valid_scopes:
                    f.write(f'{scope}\n')
                f.write('---\n')


def info():
    print("""
        ┳┓  ┓  ┏┓  •     ┓
        ┃┃┏┓┃┏┓┣ ┏┓┓┏┓┏┓┏┫
        ┻┛┗ ┗┗ ┻ ┛ ┗┗ ┛┗┗┻
                         By Axon - Hunters.security""")


if __name__ == "__main__":
    try:
        info()
        credentials = CustomCredentials(OAUTH_TOKEN)
        enumerator = ServiceAccountEnumerator(credentials, USER_EMAIL, verbose=args.verbose)
        print("\n[+] Enumerating GCP Resources: Projects and Service Accounts...")
        enumerator.list_service_accounts()
        oauth_scope_enumrator = oauth_scope_enumrator.OAuthEnumerator(USER_EMAIL, SCOPES_FILE, KEY_FOLDER, verbose=args.verbose)
        print("\n[+] Enumerating OAuth scopes and private key access tokens... (it might take a while) ")
        oauth_scope_enumrator.run()
        oauth_scope_enumrator.delete_keys_without_dwd()
        results()
    except HttpError as e:
        if e.resp.status == 401 and b"ACCESS_TOKEN_TYPE_UNSUPPORTED" in e.content:
            print("\nThe provided Bearer access token isn't valid. Refresh a new one.")
        else:
            print(f"An error occurred: {e}")