from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import DefaultCredentialsError, RefreshError
import requests
import os

KEY_FOLDER = 'SA_private_keys'

class OAuthEnumerator:
    """ Creates access token to each private key and OAuth scope and validate them"""
    def __init__(self, user_email, scopes_file, key_folder,verbose=False):
        self.user_email = user_email
        self.scopes_file = scopes_file
        self.key_folder = key_folder
        self.scopes = self.read_scopes_from_file()
        self.valid_results = {}
        self.verbose = verbose
        self.confirmed_dwd_keys = []  # Keep track of keys with DWD

    def get_valid_results(self):
        return self.valid_results

    def read_scopes_from_file(self):
        """ read OAuth scopes list from oauth_scopes.txt"""
        try:
            with open(self.scopes_file, 'r') as file:
                scopes = [line.strip() for line in file]
            return scopes
        except FileNotFoundError as fnf_error:
            print(f"Scopes file not found: {fnf_error}")
            return []
        except Exception as e:
            print(f"An error occurred while reading the scopes file: {e}")
            return []

    def validate_token(self, json_path):
        valid_scopes = []
        for scope in self.scopes:
            try:
                # Load the service account credentials
                creds = service_account.Credentials.from_service_account_file(
                    json_path,
                    scopes=[scope],
                )
                creds = creds.with_subject(self.user_email)
                # Create an access token
                creds.refresh(Request())
                # Validate the access token using tokeninfo API
                token_info_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={creds.token}"
                response = requests.get(token_info_url)

                if response.status_code == 200:
                    valid_scopes.append(scope)
                    print(f"\033[92m [+] Token is valid for {json_path} with scope {scope} \033[0m")
                    # track keys with DWD (for cleaning of the others)
                    if json_path not in self.confirmed_dwd_keys:
                        self.confirmed_dwd_keys.append(json_path)



            except DefaultCredentialsError:
                print("The service account file is not valid or doesn't exist.")
            except RefreshError as e:
                if self.verbose:
                    print(f"[-] Invalid or expired token with scope {scope}")
            self.valid_results[json_path] = valid_scopes

    def delete_keys_without_dwd(self):
        """ Delete SA keys which found without DWD from local folder"""
        for key_path in os.listdir(self.key_folder):
            full_path = os.path.join(self.key_folder, key_path)
            print("[!] Clearing private keys without DWD enabled ...")
            if full_path not in self.confirmed_dwd_keys:
                try:
                    os.remove(full_path)
                    print(f"[!] Deleted service account key without DWD: {full_path}")
                except OSError as e:
                    print(f"Error deleting {full_path}: {e}")

    def run(self):
        if not self.scopes:
            print("No scopes to check. Exiting.")
            exit()

        for json_file in os.listdir(self.key_folder):
            json_path = os.path.join(self.key_folder, json_file)
            if os.path.exists(json_path):
                self.validate_token(json_path)
            else:
                print("The json file doesn't exist.")