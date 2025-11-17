import os
import re
import sys
import json
import boto3

environment = sys.argv[1]
namespace = sys.argv[2] 
region = sys.argv[3] 
user_service_name = sys.argv[4]
user_key_name = sys.argv[5]
secret_value = sys.argv[6]
overwrite_secret_value = sys.argv[7]

#Set AWS account ids for environments
env_to_account_mapping = {
    "prod": "<aws_account_id>",
    "stage": "<aws_account_id>",
    "qa": "<aws_account_id>",
    "dev": "<aws_account_id>",
    "sbx": "<aws_account_id>", 
}
gitlab_user = os.getenv("GITLAB_USER_EMAIL")
authorized_users = [
    "<autorized_user_email>",
    "<autorized_user_email>",
    "<autorized_user_email>",
    "<autorized_user_email>"
]
#Check if the environment is entered correct and provided
if not environment:
    print(f"\nEnvironment name must be provided.")
    exit()
if environment not in ["dev", "qa"]:
    if environment in ["sbx", "stage", "prod"]:
        if gitlab_user not in authorized_users:
            print(f"Hello, {gitlab_user} !")
            print(f"You are not authorized to run job in the '{environment}' environment.")
            print(f"Please check if the provided Environment name is correct.")
            exit()

#Assume the environment role
try:
    print(f"Hello, {gitlab_user} !")
    print(f"INFO: Executing the script on environment '{environment}'.")
    print(f"INFO: Assuming the role for '{environment}'.")
    #formulate the role ARN
    ROLE_ARN = f"arn:aws:iam::{env_to_account_mapping[environment]}:role/<project>-{environment}-tf-role"
    role_session_name = "AssumedRoleSession"
    print(f"SUCCESS: Assumed the role for environment '{environment}'")
    #Create boto client for sts to assume the role
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(RoleArn=ROLE_ARN, RoleSessionName=role_session_name)
    #use the session library to store the creds for current session
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                        aws_session_token=response['Credentials']['SessionToken'])
except Exception as e:
    print(f"ERROR: error occurred while assuming the session for environment: {environment}: {e}")  
    exit(1)

if 'Credentials' in response:
    #Secret name to be created 
    secret_name = f"{environment}-{namespace}-{user_service_name}"
    #Create a secret manager client from the session
    secrets_manager_client = session.client('secretsmanager', region_name=region)

    #Check if json file exists 
    try:
        if not os.path.isfile("configs/dbAndSecrets.json"):
            print("ERROR: JSON file not found.")
            exit()
        #Read the JSON file and parse it
        with open("configs/dbAndSecrets.json", "r") as json_file:
            data = json.load(json_file)
        print("SUCCESS: JSON file found. Printing....")
        #Print the JSON file
        print(json.dumps(data, indent=2))
        #Process services in Json file
        services = data.get("services", [])
        #Loop through json file to find given service name
        for service in services:
            service_name = service.get("serviceName")
            #Check if the current service matches the user input
            if service_name == user_service_name:
                service_description = service.get("description")
                print(f"SUCCESS: Service Found....")
                print(f"Name: {service_name}")
                print(f"Description: {service_description}")
                keys = service.get("secretKeys", [])
                
                #Check if the secretKeys array is empty or not
                if keys:
                    print(f"INFO: Keys are found for service {service_name}.")
                    #Loop through the current found service to find given key name
                    for key in keys:
                        key_name = key.get("keyName")
                        #Check if the current key matches the user input
                        if key_name == user_key_name:
                            key_description = key.get("description")
                            print(f"SUCCESS: Key Found....")
                            print(f"Name: {key_name}")
                            print(f"Description: {key_description}")
                            break  #No need to continue searching for keys once found
                    else:
                        print(f"ERROR: The Key Name {user_key_name} is not found for service {service_name}.")
                        print(f"Please verify the Input or JSON file, exiting....!")
                        exit()
                else:
                    print(f"WARNING: No keys are associated with service {service_name}.")
                break  #No need to continue searching for services once found
        else:
            print(f"ERROR: The Service Name {user_service_name} is not found in JSON file.")
            print(f"Please verify the Input or JSON file, exiting....!")
            exit()
    except Exception as e:
        print(f"ERROR: error occured while checking the Json file. {e}")
        exit(1)

    #If secret value is empty that means key is also empty, then skip the the password vaidation
    if secret_value != '{}':
        if not secret_value:
            print("ERROR: Secret value cannot be empty.")
            exit()
        elif len(secret_value) > 16:
            print("ERROR: Secret value cannot be longer than 16 characters.")
            exit()
        else:
            uppercase_regex = re.compile(r'[A-Z]')
            lowercase_regex = re.compile(r'[a-z]')
            digit_regex = re.compile(r'\d')
            special_char_regex = re.compile(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]')

            if not (uppercase_regex.search(secret_value) and
                    lowercase_regex.search(secret_value) and
                    digit_regex.search(secret_value) and
                    special_char_regex.search(secret_value)):
                print("ERROR: Secret value must contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character.")
                exit()
    else:
        print("WARNING: Skipping password validation")

    try:
        #if service and keys exists but not secret then create a secret first
        try:
            response = secrets_manager_client.describe_secret(SecretId=secret_name)
            print(f"INFO: Secret {secret_name} found for environment '{environment}'. Proceeding....")
        except secrets_manager_client.exceptions.ResourceNotFoundException:
            #Create sceret if it doesnt exist
            print(f"WARNING: No secret found for {service_name} in environment '{environment}'.")
            if service_name is not None:
                #Check if JSON serviceName and User given serviceName matches
                if service_name == user_service_name:
                    print(F"INFO: Creating an empty secret for {service_name} in environment '{environment}'.")
                    #Create a Secret
                    secrets_manager_client.create_secret(Name=secret_name, SecretString='{}')
                    print(f"SUCCESS: Empty Secret '{secret_name}' created.")
                else:
                    print(f"ERROR: Invalid Service name {user_service_name}.")  
                    print(f"ERROR: Cannot create secret '{secret_name}' for given service {user_service_name}.") 
                    exit()
            else:
                print(f"ERROR: Service Name {service_name} not found")
                print(f"ERROR: Cannot create secret '{secret_name}'.") 
                print(f"Exiting....!")
                exit()
    except Exception as e:
        print(f"ERROR: error occured while creating secret '{secret_name}': {e}")
        exit(1)

    #If secret value is empty that means key is also empty, in that case skip the key insertion or updation
    if secret_value != '{}':
        try:
            #Attempt to get the secret value from secret
            response = secrets_manager_client.get_secret_value(SecretId=secret_name)
            #Parse the secret value as JSON
            response_value = json.loads(response['SecretString']) if 'SecretString' in response else {}

            try:
                #Check if the key exists in the secret, it should exist.
                #Overwrite should be 'yes' to update the existing secret.
                if key_name in response_value:
                    if overwrite_secret_value == 'yes':
                        response_value[key_name] = secret_value 
                        #Update the secret
                        secrets_manager_client.update_secret(SecretId=secret_name, SecretString=json.dumps(response_value), Description=service_description)
                        print(f"SUCCESS: The value for key Name '{key_name}' in the secret '{secret_name}' has been updated.")
                    else:
                        print(f"ERROR: The key Name '{key_name}' exists in the secret '{secret_name}', but has not been updated (OVERWRITE_SECRET_VALUE is set to 'no').")
                        exit()
            except secrets_manager_client.exceptions.ResourceNotFoundException:
                print(f"ERROR: error while updating the secret '{secret_name}': {e}")
                exit(1)

            try:
                #Check if the secret is empty or the given key should not exist.
                #Overwrite should be set to 'no' to insert the initial key-value when secret is empty. 
                #Or adding the new key-value when the given key does not exist in secret.
                if not key_name in response_value:
                    if overwrite_secret_value == 'no':    
                        response_value[key_name] = secret_value                    
                        #add new key-value into the secret
                        secrets_manager_client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(response_value))
                        print(f"SUCCESS: The key Name '{key_name}' did not exist in the secret '{secret_name}', and key-value pair has been Added.")
                    else:
                        print(f"ERROR: The key Name '{key_name}' did not exist in the secret '{secret_name}' and key-value pair has not been Added.")
                        exit()
            except secrets_manager_client.exceptions.ResourceNotFoundException:
                print(f"ERROR: error while adding key-value pair to the secret '{secret_name}': {e}")
                exit(1)          
        except Exception as e:
            print(f"ERROR: error occured while adding or updating key-value pair to the secret '{secret_name}': {e}")
            exit(1)

