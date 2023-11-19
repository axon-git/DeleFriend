
class DomainUserEnumerator:
    def __init__(self, gcp_project_enumerator):
        self.gcp_project_enumerator = gcp_project_enumerator

    def list_unique_domain_users(self):
        """List unique domain users across projects (excluding service accounts)"""
        unique_domains = {}
        for project_id in self.gcp_project_enumerator.get_projects():
            resource_manager_service = self.gcp_project_enumerator.resource_manager_service
            request = resource_manager_service.projects().getIamPolicy(resource=project_id, body={})
            response = request.execute()

            if 'bindings' in response:
                for binding in response['bindings']:
                    if 'members' in binding:
                        for member in binding['members']:
                            if member.startswith('user:'):
                                email = member.split(':')[1]
                                # exclude GCP service accounts
                                if '@' in email and not email.endswith('.gserviceaccount.com'):
                                    domain = email.split('@')[1]
                                    if domain not in unique_domains:
                                        unique_domains[domain] = email
        return unique_domains


    def print_unique_domain_users(self):
        unique_domain_users = self.list_unique_domain_users()
        if unique_domain_users:
            print("\n[+] Unique domain IAM users for creating valid JWT objects to Google Workspace found ...")
            for domain, user in unique_domain_users.items():
                print(f"Domain: {domain}, User: {user}")
        else:
            print("\nNo unique domain IAM users found in the specified projects.")
