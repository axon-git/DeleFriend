import os
import json
from googleapiclient.discovery import build
import base64

class PrivateKeyCreator:
    """ Creates GCP private key pairs for SAs with permissions """
    def __init__(self, credentials):
        self.credentials = credentials
        self.iam_service = build('iam', 'v1', credentials=self.credentials)
        self.keys_directory = "SA_private_keys"
        os.makedirs(self.keys_directory, exist_ok=True)


    def create_service_account_key(self, service_account):
        key = self.iam_service.projects().serviceAccounts().keys().create(
            name=service_account,
            body={
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
            }
        ).execute()

        # The private key data is a base64-encoded JSON string within the attr privateKeyData
        key_json = base64.b64decode(key['privateKeyData']).decode('utf-8')
        key_data = json.loads(key_json)

        file_name = service_account.replace('/', '_').replace(':', '_')
        file_path = os.path.join(self.keys_directory, f"{file_name}.json")
        with open(file_path, "w") as file:
            json.dump(key_data, file)  # Save the decoded key data, not the entire key object

        print(f"\033[92m \tKey created and saved to {file_path} \033[0m")