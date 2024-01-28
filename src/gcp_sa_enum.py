import requests
from googleapiclient.discovery import build
from src.private_key_creator import PrivateKeyCreator



class ServiceAccountEnumerator:
    """Enumerate GCP Projects and Service Accounts and find roles with iam.serviceAccountKeys.create permission  """
    def __init__(self, credentials, verbose=False):
        self.credentials = credentials
        self.resource_manager_service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
        self.iam_service = build('iam', 'v1', credentials=self.credentials)
        self.user_email = self.get_iam_email_from_token()
        self.key_creator = PrivateKeyCreator(credentials)
        self.verbose = verbose

    def get_iam_email_from_token(self):
        """Get the email (or SA email identifier) associated with the access token provided in order to check for the user relevant role and permissions"""
        try:
            response = requests.get(
                'https://www.googleapis.com/oauth2/v1/tokeninfo?alt=json',
                headers={'Authorization': f'Bearer {self.credentials.token}'}
            )
            response.raise_for_status()
            token_info = response.json()
            # Service Account access tokens return different token parameters, here we use 'azp' (issued_to) to find the matching service account email
            if 'email' not in token_info:
                azp = token_info.get('issued_to')
                return self.find_service_account_email_by_client_id(azp) if azp else None
            return response.json().get('email')
        except requests.RequestException as e:
            print(f"Error fetching user info: {e}")
            return None

    def find_service_account_email_by_client_id(self, client_id):
        """Find the target service account email by matching the oauth2ClientId and azp values. This function relevant only for SA access tokens"""
        for project_id in self.get_projects():
            request = self.iam_service.projects().serviceAccounts().list(
                name='projects/' + project_id,
            )
            response = request.execute()
            if 'accounts' in response:
                for account in response['accounts']:
                    sa_details = self.get_service_account_details(account['name'])
                    if sa_details and sa_details.get('oauth2ClientId') == client_id:
                        return account['email']
        return None

    def get_service_account_details(self, service_account_name):
        """Get detailed information about the service account, including the oauth2ClientId. This function relevant only for SA access tokens"""
        request = self.iam_service.projects().serviceAccounts().get(name=service_account_name)
        try:
            response = request.execute()
            return response
        except Exception as e:
            print(f"Error retrieving service account details: {e}")
            return None

    def get_service_account_roles(self, service_account):
        """Get the roles on the target Service Account resources from the IAM Policy"""
        request = self.iam_service.projects().serviceAccounts().getIamPolicy(  # Get roles of the target SA
            resource=service_account,
        )
        response = request.execute()
        roles = []

        if 'bindings' in response:
            for binding in response['bindings']:
                if 'members' in binding:
                    for member in binding['members']:
                        # Extract the email or serviceaccount identifier part after the ':' character
                        _, member_identifier = member.split(':', 1)
                        # Check if the extracted identifier matches the token user email to understand if it has the role
                        if member_identifier == self.user_email:
                            roles.append(binding['role'])
        return roles

    def get_project_roles(self, project_id):
        """Get Project-level roles of the IAM User/SA from the IAM Policy"""
        request = self.resource_manager_service.projects().getIamPolicy(
            resource=project_id,
            body={}
        )
        response = request.execute()
        roles = []

        if 'bindings' in response:
            for binding in response['bindings']:
                if 'members' in binding:
                    for member in binding['members']:
                        # Extract the email or serviceaccount identifier part after the ':' character
                        _, member_identifier = member.split(':', 1)

                        # Check if the extracted identifier matches the token user email to understand if it has the role
                        if member_identifier == self.user_email:
                            roles.append(binding['role'])

        return roles


    def get_projects(self):
        try:
            request = self.resource_manager_service.projects().list() # Get list of target projects
            response = request.execute()
            return [project['projectId'] for project in response['projects']]

        except Exception as e:
            print(f"Failed to get projects: {e}")
            raise e


    def check_permission(self, role):
        """ Check if the target role has iam.serviceAccountKeys.create permission """

        # custom role validation - custom roles starting with the following format projects/<project_name>
        if "projects/" in role:
            request = self.iam_service.projects().roles().get(name=role)
        # basic or predefined roles
        else:
            request = self.iam_service.roles().get(name=role)

        response = request.execute()
        permissions = response.get('includedPermissions', [])
        return 'iam.serviceAccountKeys.create' in permissions

    def enumerate_service_accounts(self):
        any_service_account_with_key_permission = False
        for project_id in self.get_projects():
            request = self.iam_service.projects().serviceAccounts().list(name='projects/' + project_id)
            response = request.execute()
            if 'accounts' in response:
                for account in response['accounts']:
                    project_roles = self.get_project_roles(project_id)
                    service_account_roles = self.get_service_account_roles(account['name'])
                    all_roles = list(set(project_roles + service_account_roles))
                    if any(self.check_permission(role) for role in all_roles):
                        self.print_service_account_details(account, all_roles)
                        self.key_creator.create_service_account_key(account['name'])
                        any_service_account_with_key_permission = True
                    elif self.verbose:
                        self.print_service_account_details(account)
                        print('\033[91m' + '\tNo relevant roles found' + '\033[0m')
                        print('---')
        if not any_service_account_with_key_permission:
            print("No GCP Service Accounts roles found with the relevant key permissions")

    def print_service_account_details(self, account, roles=None):
        print('Name: ' + account['name'])
        print('Email: ' + account['email'])
        print('UniqueId: ' + account['uniqueId'])
        if roles:
            print('Roles: ', ', '.join(roles))

