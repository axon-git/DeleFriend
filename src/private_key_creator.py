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

    def delete_remote_key(self, key_name):
        """ Delete the remote service account key """
        try:
            self.iam_service.projects().serviceAccounts().keys().delete(name=key_name).execute()
            print(f"[!] Successfully deleted remote service account key: {key_name}")
        except Exception as e:
            print(f"Error deleting remote key {key_name}: {e}")

    def delete_keys_without_dwd(self, confirmed_dwd_keys):
        """ Delete SA keys which found without DWD from local folder and remotely"""
        print("[!] Clearing private keys without DWD enabled ...")
        for key_path in os.listdir(self.keys_directory):
            full_path = os.path.join(self.keys_directory, key_path)
            if full_path not in confirmed_dwd_keys:
                try:
                    # Delete the key remotely
                    with open(full_path, 'r') as key_file:
                        key_data = json.load(key_file)
                        client_email = key_data["client_email"]
                        key_id = key_data["private_key_id"]
                        project_id = key_data["project_id"]
                        # API is expecting the following format projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}/keys/{KEY_ID}
                        resource_name = f"projects/{project_id}/serviceAccounts/{client_email}/keys/{key_id}"
                        self.delete_remote_key(resource_name)
                    # Delete the key locally
                    os.remove(full_path)
                    print(f"[!] Deleted local service account key without DWD: {full_path}")
                except OSError as e:
                    print(f"Error deleting {full_path}: {e}")