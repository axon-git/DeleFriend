from googleapiclient.discovery import build
from private_key_creator import PrivateKeyCreator


class ServiceAccountEnumerator:
    """Enumerate GCP Projects and Service Accounts and find roles with iam.serviceAccountKeys.create permission  """
    def __init__(self, credentials, user_email):
        self.credentials = credentials
        self.user_email = user_email
        self.iam_service = build('iam', 'v1', credentials=self.credentials)
        self.resource_manager_service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
        self.key_creator = PrivateKeyCreator(credentials)

    def get_service_account_roles(self, service_account):
        request = self.iam_service.projects().serviceAccounts().getIamPolicy( # Get roles of the target SA
            resource=service_account,
        )
        response = request.execute()
        roles = []

        if 'bindings' in response:
            for binding in response['bindings']:
                if 'members' in binding:
                    for member in binding['members']:
                        if 'user:' + self.user_email in member:
                            roles.append(binding['role'])
        return roles

    def get_project_roles(self, project_id):
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
                        if 'user:' + self.user_email in member:
                            roles.append(binding['role'])
        return roles

    def get_projects(self):
        request = self.resource_manager_service.projects().list() # Get list of target projects
        response = request.execute()
        return [project['projectId'] for project in response['projects']]

    def check_permission(self, role):
        """ Check if the target role has iam.serviceAccountKeys.create permission """
        request = self.iam_service.roles().get(name=role)
        response = request.execute()
        permissions = response.get('includedPermissions', [])
        return 'iam.serviceAccountKeys.create' in permissions

    def list_service_accounts(self):
        print("\nGCP Service Accounts:")
        any_service_account_with_key_permission = False
        for project_id in self.get_projects():
            request = self.iam_service.projects().serviceAccounts().list(
                name='projects/' + project_id,
            )
            response = request.execute()

            if 'accounts' in response:
                for account in response['accounts']:
                    print('Name: ' + account['name'])
                    print('Email: ' + account['email'])
                    print('UniqueId: ' + account['uniqueId'])
                    print('Roles: ')

                    project_roles = self.get_project_roles(project_id)
                    service_account_roles = self.get_service_account_roles(account['name'])
                    all_roles = list(set(project_roles + service_account_roles))

                    key_created = False
                    no_roles_found = True

                    for role in all_roles: # check for roles for the IAM
                        print('\t' + role)
                        no_roles_found = False

                        # If the role has the permission to create keys
                        if self.check_permission(role) and not key_created:
                            print('\033[92m' + '\tKey can be created' + '\033[0m')
                            self.key_creator.create_service_account_key(account['name'])
                            key_created = True  # After key creation, set the flag to True to avoid duplications
                            any_service_account_with_key_permission = True
                        else:
                            print('\033[91m' + '\tNo required permission' + '\033[0m')

                    if no_roles_found:
                        print('\033[91m' + '\tNo roles found' + '\033[0m')

                    print('---')
        if not any_service_account_with_key_permission:
            print("No GCP Service Accounts roles found with the relevant key permissions")