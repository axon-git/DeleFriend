# DeleFriend
```                                    
  ┳┓  ┓  ┏┓  •     ┓
  ┃┃┏┓┃┏┓┣ ┏┓┓┏┓┏┓┏┫
  ┻┛┗ ┗┗ ┻ ┛ ┗┗ ┛┗┗┻
       By Axon - Hunters.security
```

  ![image text](https://github.com/axon-git/DeleFriend/blob/main/DeleFriend%2022.11%20v2%20concept.jpg)


## Description
Delefriend is a proof-of-concept red team tool to automatically find and abuse existing GCP service accounts with domain-wide delegation (DWD) on Google Workspace by smartly fuzzing all of the existing JWT combinations that are relevant to the initial GCP identity. A compromised GCP service account key with DWD enabled can be used to perform API calls on all of the identities in the target Workspace domain. 

### Disclaimer
Delefriend was created as a proof-of-concept tool to increase awareness around OAuth delegation attacks in GCP and Google Workspace and to improve the security posture of organizations that use the Domain-Wide-Delegation feature. Delefriend should be used solely for authorized security research purposes. This tool is provided “as is” and Hunters.secuity disclaims any and all warranties and liabilities regarding the use/misuse of this tool. Use responsibly.


## <b> How It works </b>
1. Enumerate GCP Projects using Resource Manager API. 
2. Iterate on each project resource, and enumerate GCP Service account resources to which the initial IAM user (the provided access token) has access using `GetIAMPolicy`.
3. Iterate on each service account role, and find built-in, basic, or custom roles with `serviceAccountKeys.create` permission on the target resource. 
4. Create a new `KEY_ALG_RSA_2048` private key to each service account resource found with relevant permission in the IAM policy.
5. In case no target Workspace is provided in the config YAML, the tool will enumerate all the available project resources to find distinct organizational domains workspace users. Consequently, creating a JWT for any domain user affects all identities in that domain, consistent with our combination enumeration check. Simply put, one valid Workspace user is adequate to move forward.
7. Iterate on each new service account and create a `JWT` object for it which is composed of the SA private key credentials, OAuth scope, and target workspace subject(s). The process of creating a new `JWT` object will iterate on all the existing combinations of OAuth scopes from `oauth_scopes.txt` list, and distinct domain org subject users in order to find all the delegation possibilities. 
8. Enumerate and create a new bearer access token for each `JWT` combination and validate the token against `tokeninfo()` API. A successful match will return 200, and provide to the user the exact combination that is relevant for delegation - Private Key, OAuth Scope, and Workspace Domain.
9. You can use the combination to access Google APIs and perform various actions on the Workspace on behalf of all the identities in the domain. The actions are related to the OAuth scopes that are attached to the delegation, you can read more about it in Google's developers docs https://developers.google.com/identity/protocols/oauth2/scopes

### Root Cause
When a new domain delegation configuration is created, it is defined by the service account resource identification (the OAuth ID) and not by the specific private key/s attached to the SA identity. This means that in case an IAM identity has access to create new private keys to a relevant GCP service account resource that has existing domain-wide delegation permissions, a fresh private key can be abused to perform API calls to Google Workspace on behalf of other identities in the domain. The POC provides a programmatic and elegant approach to finding all of the existing delegations based on the permissions of the provided GCP IAM identity. 

For a detailed technical deep dive into the feature, check out our blog post: https://www.hunters.security/en/blog/delefriend-a-newly-discovered-design-flaw-in-domain-wide-delegation-could-leave-google-workspace-vulnerable-for-takeover


## How to use
DeleFriend uses Poetry to allow easy and fast dependency installation. 

- Set up relevant packages and dependencies using Poetry. 
```
git clone git@github.com:axon-git/DeleFriend.git <your-local-repos-dir>/DeleFriend
cd <your-local-repos-dir>/DeleFriend
poetry shell 
poetry install
```

- Configure the GCP access token and target workspace user in the `config.yaml` file.
- The target `workspace_user_email` parameter is optional. In case you are not familiar with a target workspace user, the tool will try to automatically find one using role enumeration on the relevant projects.
```
bearer_access_token: "ya29.a0AfB_byAqJqwhrdICHDuboC_iG5EIjDY6RabfbhuXvLV-Q5iSEUNgvj0XqRDaUKWz-RHJyk3ZWUhEg7DddfsSpMTRViUspGOhi3jheezbhxuTyIY5sz6UxfoV0OR1y49EWXfqBpGMxwg96bBsc9PwCIYHlyql0H7vQl1Ue3b8VGGBaCgYKAR0SARISFQHGX2MiQn..."
# OPTIONAL parameter of a target workspace user (use only in case you know at least one valid workspace email, if not - the tool will automatically find for you)
#workspace_user_email: "user@domain.com"
```
- Run the tool (—verbose/-v option can be used for verbose or debugging mode)
```
python main.py -c config.yaml  —v
```

