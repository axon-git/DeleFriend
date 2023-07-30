# DeleFriend
```                                    
  ┳┓  ┓  ┏┓  •     ┓
  ┃┃┏┓┃┏┓┣ ┏┓┓┏┓┏┓┏┫
  ┻┛┗ ┗┗ ┻ ┛ ┗┗ ┛┗┗┻
       By Axon - Hunters.security
```

## Description
Delefriend is a proof-of-concept red team tool to automatically find and abuse existing GCP service accounts with domain-wide delegation (DWD) on Google Workspace. 

### Disclaimer
Delefriend was written as a proof-of-concept tool to increase awareness around OAuth delegations attacks in GCP and Google Workspace, and in order to improve the security and the posture of organizations that are using the Domain-Wide-Delegation feature. Delefriend should be used only for authorized security testing engagements, and Hunters.security doesn’t take any responsibility for any malicious usage that might be done using the tool.


## <b> How It works </b>
1. Enumerate GCP Projects using Resource Manager API. 
2. Iterate on each project resource, and enumerate GCP Service account resources to which the initial IAM user has access using `GetIAMPolicy`.
3. Iterate on each service account role, and find built-in roles or basic roles with `serviceAccountKeys.create` permission on the target resource. (Next version will include a method of doing it on custom roles as well)
4. Create a new `KEY_ALG_RSA_2048` private key to each service account resource which is found with relevant permission in the IAM policy. 
5. Iterate on each new service account and create a `JWT` object for it which is composed of the SA private key credentials and OAuth scope. The process of creating a new `JWT` object will iterate on all the existing combinations of OAuth scopes from `oauth_scopes.txt` list, in order to find all the delegation possibilities. 
6. Enumerate and create a new bearer access token for each `JWT` and validate the token against `tokeninfo()` API.

### Root Cause
When a new domain delegation configuration is created, it is defined by the service account resource identification (the OAuth ID) and not by the specific private key/s attached to the SA identity. This means that in case an IAM identity has access to create new private keys to a relevant GCP service account resource that has existing domain-wide delegation permissions, a fresh private key can be abused to perform API calls to Google Workspace on behalf of other identities in the domain.

For a detailed technical deep dive into the feature, check out our blog post: ………..


## How to use
DeleFriend uses Poetry to allow easy and fast dependency installation. 

- Set up relevant packages and dependencies using Poetry. 
```
git clone git@github.com:axon-git/DeleFriend.git <your-local-repos-dir>/DeleFriend
cd <your-local-repos-dir>/DeleFriend
poetry shell 
poetry install
```

- Configure the GCP access token and email identifier of the checked IAM user in the `config.yaml` file.
```
oauth_token: "ya29.a0AbVbY6ObhjFsDPA8tWjgwAKCRwdggbn9orsCBNYXZckWLFac1gJnc_16i9ybCNWT-geixKeDxGvP0K4RxxsR8uEKfkK-P48W1DVOs18SvfXkmrBW1sScYgAOIuecXI44zNOqPkzsX0bIsFXVgHyuSro04pW9kH3gKzE10gaCgYKAXISARASFQFWKvPlnmftnAGjbLMXAegDBLlovQ0173"
user_email: “user@axonland.com"
```
- Run the tool (—verbose/-v option can be used for verbose or debugging mode)
```
python main.py -c config.yaml  —v
```


## Contribution 
We are encouraged security researchers and any cloud enthusiasts to contribute to the project and assist with the tool development. 


## Future Plans:
- Support service accounts identities as an initial vector - we understand that compromised service accounts are common in red team engagements, and as a result, will add support for them in the next versions of the tool.
- Support custom rule enumration - we understand that custom roles have a huge potential to contain permission misconfigurations of serviceAccountKeys.create, and as a result, will add support for enumerating custom roles as well in the next versions of the tool.
