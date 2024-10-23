#    Copyright 2024 Walacor Corporation

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import boto3
from botocore.config import Config

import requests
import hashlib
import sys
import logging
import json
import time
import os

#region Command Line Parms

# Command Line Parms
# 1 - Mode (1=make sig, 2=validate sig) I.E. 1
# 2 - Source (1=Local File, 2=S3) I.E. 1
# 3 - Walacor API endpoint root I.E. https://dev-platform.epcone.com
# 4 - Walacor API user I.E. rain
# 5 - Walacor API password I.E. XXXX
# 6 - Log File Name I.E. S3DirHash_Log.txt
# 7 - Log Level (10,20,30,40,50)
# 8 - Root (the root location to work from) I.E. /ai-ml-model-artifacts
# 9 - Specific Model I.E. attention_a6_korea
# 10 - s3 endpoint I.E. Something specific if not a standard S3 endpoint (Might not be necessary)
# 11 - s3 Access Key 
# 12 - s3 Secret Key
# 13 - s3 region I.E. us-gov-west-1
# 14 - s3 bucket I.E. ultra-walacor

#endregion

#region Walacor

def W_ManageDirHashRecord(sdir, dir_hash, dir_contents_hash):
    sNameHashRecord = W_GetNameHash(dir_hash)

    if not sNameHashRecord:
        #New Record
        sNameHashRecord = W_BlankNameHash()
        sNameHashRecord['Version'] = 1
        sNameHashRecord['NameHash'] = dir_hash
        sNameHashRecord['ContentsHash'] = dir_contents_hash
        sNameHashRecord['LastSourceCheck'] = get_EpochTime()

        W_UpdateNameHash(sNameHashRecord)
        logger.warning('Dir Contents Hash not found, Creating new record - ' + sdir + ' - ' + dir_contents_hash)
    else:
        sNameHashRecordUpdate = {}
        sNameHashRecordUpdate['UID'] = sNameHashRecord['UID'] 
        sNameHashRecordUpdate['LastSourceCheck'] = get_EpochTime()

        if sNameHashRecord['ContentsHash'] == dir_contents_hash:
            logger.info('Dir Contents Hash is the same, Updating source Check Date - ' + sdir + ' - ' + dir_contents_hash)
        else:
            logger.warning('Dir Contents Hash is different, Updating version - ' + sdir + ' - ' + dir_contents_hash)
            sNameHashRecordUpdate['Version'] = sNameHashRecord['Version'] + 1
            sNameHashRecordUpdate['ContentsHash'] = dir_contents_hash

        W_UpdateNameHash(sNameHashRecordUpdate)

def W_ManageValidation(sdir, dir_hash, dir_contents_hash):
    sNameHashRecord = W_GetNameHash(dir_hash)

    intRet = 0

    if not sNameHashRecord:
        #New Record
        sNameHashRecord = W_BlankNameHash()
        sNameHashRecord['Version'] = 1
        sNameHashRecord['NameHash'] = dir_hash
        sNameHashRecord['ContentsHash'] = dir_contents_hash
        sNameHashRecord['LastSourceCheck'] = get_EpochTime()

        logger.critical('Dir Contents Hash not found, Validation Failed - ' + sdir)
        intRet = 1
    else:
        sNameHashRecordUpdate = {}
        sNameHashRecordUpdate['UID'] = sNameHashRecord['UID'] 

        if sNameHashRecord['ContentsHash'] == dir_contents_hash:
            logger.warning('Dir Contents Hash is the same, validation successful, updating validation date - ' + sdir)
            sNameHashRecordUpdate['LastVerification'] = get_EpochTime()
            W_UpdateNameHash(sNameHashRecordUpdate)
        else:
            logger.critical('Dir Contents Hash is different, Validation Failed - ' + sdir)
            intRet = 1

    return intRet

def WGet_Bearer(serverurl, username, password):
    # Define the URL and headers
    headers = {
        'Content-Type': 'application/json'
    }

    global walacor_Bearer
    global walacor_Bearer_Expiration

    # Define the payload with your username and password
    payload = {
        'userName': username,
        'password': password
    }

    # Make the POST request to get the token
    response = requests.post(serverurl + '/auth/login', headers=headers, data=json.dumps(payload))

    # Check if the request was successful
    if response.status_code == 200:
        # Assuming the token is in the 'token' field of the JSON response
        token = response.json().get('api_token')
        
        if token:
            # Store the token in a file for later use
            walacor_Bearer = token
            walacor_Bearer_Expiration = get_EpochTime() + 3600  # set timeout to 1 hr
            logger.info("Token stored successfully.")
        else:
            logger.debug("Token not found in the response.")
    else:
        logger.error(f"Failed to retrieve token: {response.status_code} - {response.text}")

def W_EnsureLoggedIn():
    bolNeedNew = False

    if not walacor_Bearer:
        bolNeedNew = True

    if walacor_Bearer_Expiration < get_EpochTime():
        bolNeedNew = True

    if bolNeedNew:
        WGet_Bearer(walacor_endpoint,walacor_user,walacor_password)

def W_EnsureSchema():

    if W_CheckForSchema():
        return

    W_EnsureLoggedIn()

    # Define the URL and headers
    headers = {
        'Content-Type': 'application/json',
        'ETId' : '50',
        'SV' : '1',
        'Authorization' : walacor_Bearer
    }

    # Define the payload 
    payload = {
                "ETId": 50,
                "SV": 1,
                "Schema": {
                "ETId": 1500000,
                    "TableName": "ObjectHash",
                    "Family": "Object Validation",
                    "Description": "Stores a list of hashes for each item to be used later to validate the integrity of the objects",
                    "DoSummary": True,
                    "Fields": [
                        {
                            "FieldName": "NameHash",
                            "DataType": "TEXT",
                            "MaxLength": 1024,
                            "Required": True,
                            "Description": "Hash of the object name. (A directory)"
                        },
                        {
                            "FieldName": "ContentsHash",
                            "DataType": "TEXT",
                            "MaxLength": 1024,
                            "Required": True,
                            "Description": "Hash of the objects contents. (A directories contents)"
                        },
                        {
                            "FieldName": "Version",
                            "DataType": "INTEGER",
                            "Required": False,
                            "Description": "When a new contentshash is generated for a Namehash this is incremented"
                        },
                        {
                            "FieldName": "LastSourceCheck",
                            "DataType": "DATETIME(EPOCH)",
                            "Required": False,
                            "Description": "When an existing contentshash is generated for a Namehash this is updated"
                        },
                        {
                            "FieldName": "LastVerification",
                            "DataType": "DATETIME(EPOCH)",
                            "Required": False,
                            "Description": "When a contentshash is verfied for a Namehash this is updated"
                        }
                    ],
                    "Indexes": [
                        {
                            "Fields": [
                                "NameHash"
                            ],
                            "IndexValue": "NameHash",
                            "ForceUpdate": False,
                            "Delete": True
                        }
                    ], 
                }
    }
     # Make the POST request to get the token
    
    response = requests.post(walacor_endpoint + '/schemas/', headers=headers, data=json.dumps(payload))

    # Check if the request was successful
    if response.status_code == 200:
        # Assuming the token is in the 'token' field of the JSON response
        jresponse = json.loads(response.text)
        sUID = jresponse['data']['UID'][0]

        if sUID:
            # Store the token in a file for later use
            logger.info("Schema stored sucessfully - " + sUID)
        else:
            logger.debug("Schema not stored sucessfully - " + sUID)
    else:
        logger.error(f"Failed to submit schema: {jresponse['success']} - {jresponse['error']}")

def W_CheckForSchema():
    W_EnsureLoggedIn()

    # Define the URL and headers
    headers = {
        'Content-Type': 'application/json',
        'ETId' : '1500000',
        'Authorization' : walacor_Bearer
    }

     # Make the get request    
    response = requests.get(walacor_endpoint + '/schemas/envelopeTypes/1500000/details', headers=headers, data='')

    # Check if the request was successful
    if response.status_code == 200:
        return True
    else:
        return False

def W_BlankNameHash():
    return {
        'NameHash': '',
        'ContentsHash' : '',
        'Version' : 0,
        'LastSourceCheck' : None,
        'LastVerification' : None
        }

def W_GetNameHash(sNameHash):

    W_EnsureLoggedIn()

    # Define the URL and headers
    headers = {
        'Content-Type': 'application/json',
        'ETId' : '1500000',
        'Authorization' : walacor_Bearer
    }

    # Define the payload 
    payload = {
                "NameHash": sNameHash,
            }
    
     # Make the POST request to get the query
    
    response = requests.post(walacor_endpoint + '/query/get?fromSummary=true', headers=headers, data=json.dumps(payload))

    # Check if the request was successful
    if response.status_code == 200:
        jresponse = json.loads(response.text)
        
        if jresponse['data']:
            sUID = jresponse['data'][0]['UID']
            logger.info("NameHash Found - " + sUID)
            return jresponse['data'][0]
        else:
            logger.info("NameHash Not Found - " + sNameHash)
            return ''
    else:
        logger.error(f"Failed to Query {jresponse['success']} - {jresponse['error']}")
        return ''
    
def W_UpdateNameHash(sNameHashRecord):

    W_EnsureLoggedIn()

    # Define the URL and headers
    headers = {
        'Content-Type': 'application/json',
        'ETId' : '1500000',
        'Authorization' : walacor_Bearer
    }
    
    payload = {
        'Data': [
            sNameHashRecord
        ]
    }

    # Make the POST request to get the query
    response = requests.post(walacor_endpoint + '/envelopes/submit', headers=headers, data=json.dumps(payload))

    # Check if the request was successful
    if response.status_code == 200:
        jresponse = json.loads(response.text)
        
        if jresponse['data']:
            sUID = jresponse['data']['UID'][0]
            logger.info("NameHash Submitted - " + sUID)

    else:
        logger.error(f"Failed to submit {jresponse['success']} - {jresponse['error']}")

#endregion

#region S3

def s3_setup():
    config = Config(
        
        region_name = s3_region,
        signature_version = 'v4',
        retries = {
            'max_attempts': 10,
            'mode': 'standard'
        }
    )
    return boto3.client('s3', config=config, aws_access_key_id=s3_access, aws_secret_access_key=s3_secret)

def s3_list_directories(s3_client, bucket_name, prefix=''):
    paginator = s3_client.get_paginator('list_objects_v2')
    directories = set()

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix + '/', Delimiter='/'):
        for common_prefix in page.get('CommonPrefixes', []):
            strPrefix = common_prefix['Prefix'].replace(prefix + '/', '')[:-1]
            directories.add(strPrefix)

    return list(directories)

def s3_hash_dir_contents(s3_client, s3_bucket, ldirs):
    sha2_hash = hashlib.sha256()
    continuation_token = ''

    objects2 = []

    while True:
        if len(ldirs) == 0:
            break

        s3_dir = ldirs[0] + '/'

        while True:
            if continuation_token:
                objects = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_dir, ContinuationToken=continuation_token)
            else:
                objects = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_dir)

            # for page in page_iterator:
            #     for obj in page.get('Contents', []):
            #         objects.append(obj['Key'])

            # objects.sort()

            for obj in objects['Contents']:
                key = obj['Key']

                if not key.endswith('/'):
                    if not key in objects2:
                        objects2.append(key)

                # if key.endswith('/'):
                #     if key != s3_dir:
                #         ldirs.append(key)
                # else:
                #     if not key in objects2:
                #         objects2.append(key)

            if objects.get('IsTruncated'):  # Check if there are more objects
                continuation_token = objects.get('NextContinuationToken')
            else:
                break
        
        ldirs.pop(0)
    
    objects2.sort()

    for obj in objects2:
        logger.debug('S3 - Hash File - ' + obj)

        s3_hash_object_stream(s3_bucket, obj, sha2_hash)
        #s3_hash_object_local(s3_bucket, obj, sha2_hash)

    return sha2_hash.hexdigest()

def s3_hash_object_stream(s3_bucket, s3_key, hash_object):

    # Streaming data from S3
    response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
    body = response['Body']

    # Read the data in chunks
    while True:
        chunk = body.read(1024 * 1024 * 10)  # Read 10 MB at a time
        if not chunk:
            break
        hash_object.update(chunk)

def s3_hash_object_local(s3_bucket, s3_key, hash_object):

    # Streaming data from S3
    s3_client.download_file(s3_bucket, s3_key, "tempfile")

    with open("tempfile", 'rb') as file:  # Open in binary mode = rb
        while True:
            # Read a chunk of data
            chunk = file.read(1024 * 1024 * 10)  # Read 1024 bytes at a time
            if not chunk:
                break  # End of file
            # Process the chunk (e.g., print the byte data)
            hash_object.update(chunk)
            #sha2_hash.update(chunk)
    
    os.remove("tempfile")

    # response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key, 
    # body = response['Body']

    # # Read the data in chunks
    # while True:
    #     chunk = body.read(1024 * 1024 * 10)  # Read 10 MB at a time
    #     if not chunk:
    #         break
    #     hash_object.update(chunk)

#endregion

#region Filesystem

def fs_hash_files_in_dir(directory):
    sha2_hash = hashlib.sha256()
    
    objects2 = []

    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)

            if os.path.isfile(file_path):

                if not file_path in objects2:
                    objects2.append(file_path)

    objects2.sort()

    for obj in objects2:
        logger.debug('FS - Hash File - ' + obj)
        with open(obj, 'rb') as file:  # Open in binary mode = rb
            while True:
                # Read a chunk of data
                chunk = file.read(1024 * 1024 * 10)  # Read 1024 bytes at a time
                if not chunk:
                    break  # End of file
                # Process the chunk (e.g., print the byte data)
                sha2_hash.update(chunk)
                #sha2_hash.update(chunk)

    return sha2_hash.hexdigest()

#endregion

#region Utility

def get_parameter(intParmPos):
    if (len(sys.argv) - 1) < intParmPos or sys.argv[intParmPos] is None:
        return None  # Return None if the parameter is not provided
    else:
        return sys.argv[intParmPos]  # Return the parameter if it exists

def yenc_encode(string):
    encoded = bytearray()
    for char in string:
        encoded.append((ord(char) + 42) % 256)
    return encoded

def yenc_decode(encoded):
    decoded = ""
    for byte in encoded:
        decoded += chr((byte - 42) % 256)
    return decoded

def setup_logger(log_file, log_level):
    intLogLevel = int(log_level)

    logger = logging.getLogger('my_logger')
    logger.setLevel(intLogLevel)

    # Create file handler
    if log_file != '':
        file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(intLogLevel)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(intLogLevel)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s', '%Y%m%d - %H:%M:%S')

    # Add formatter to handlers
    if log_file != '':
        file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    if log_file != '':
        logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def get_EpochTime():
    return time.time()

def hash_string(strIn):
    sha2_dir_hash = hashlib.sha256()
    sha2_dir_hash.update(yenc_encode(strIn))
    return sha2_dir_hash.hexdigest()

#endregion

walacor_Bearer = ''
walacor_Bearer_Expiration = 0.0

if __name__ == "__main__":
    
    prog_mode = int(get_parameter(1))
    source_type = int(get_parameter(2))
    walacor_endpoint = get_parameter(3)
    walacor_user = get_parameter(4)
    walacor_password = get_parameter(5)
    log_filename = get_parameter(6)
    log_level = int(get_parameter(7))
    source_root = get_parameter(8)
    focus_model = get_parameter(9)
    s3_endpoint = get_parameter(10)
    s3_access = get_parameter(11)
    s3_secret = get_parameter(12)
    s3_region= get_parameter(13)
    s3_bucket = get_parameter(14)

    logger = setup_logger(log_filename,log_level)

    W_EnsureSchema()

    ldirs = []

    if prog_mode == 1:
        logger.info('*******  Generation *******')
        if source_type == 1:
            # we are generating for local file system
            ldirs = [d for d in os.listdir(source_root) if os.path.isdir(os.path.join(source_root, d))]

        elif source_type == 2:
            # we are generating for an s3 source
             # login to s3
            s3_client = s3_setup()        
            # Get dir list from root
            ldirs = s3_list_directories(s3_client, s3_bucket, source_root)       

        for sdir in ldirs:
            # Hash the dir name
            sha2_dir_hash = hashlib.sha256()

            logger.info('Starting - ' + sdir)
            dir_hash = hash_string(sdir)

            logger.info('Dir Hash - ' + sdir + ' - ' + dir_hash)

            # Hash the dir contents
            dir_contents_hash = ''
            if source_type == 1:
                dir_contents_hash = fs_hash_files_in_dir(source_root + '/' + sdir)
            elif source_type == 2:
                dir_contents_hash = s3_hash_dir_contents(s3_client, s3_bucket, [source_root + '/' + sdir])

            logger.info('Dir Contents Hash - ' + sdir + ' - ' + dir_contents_hash)

            W_ManageDirHashRecord(sdir, dir_hash, dir_contents_hash)

            logger.info('Finished - ' + sdir)

    elif prog_mode == 2:
        logger.info('*******  Validation *******')
        # we are verfifying existing hashes
        if source_type == 1:
            # we are generating for local file system
            ldirs = [d for d in os.listdir(source_root) if os.path.isdir(os.path.join(source_root, d))]

        elif source_type == 2:
            # we are generating new and updated hashes from an s3 source
             # login to s3
            s3_client = s3_setup()        
            # Get dir list from root
            ldirs = s3_list_directories(s3_client, s3_bucket, source_root)    

        intRet = 0

        # Process the directories
        for sdir in ldirs:

            logger.info('Starting - ' + sdir)
            dir_hash = hash_string(sdir)

            logger.info('Dir Hash - ' + sdir + ' - ' + dir_hash)

            # Hash the dir contents
            dir_contents_hash = ''
            if source_type == 1:
                dir_contents_hash = fs_hash_files_in_dir(source_root + '/' + sdir)
            elif source_type == 2:
                dir_contents_hash = s3_hash_dir_contents(s3_client, s3_bucket, [source_root + '/' + sdir])

            logger.info('Dir Contents Hash - ' + sdir + ' - ' + dir_contents_hash)

            if W_ManageValidation(sdir, dir_hash, dir_contents_hash) != 0:
                intRet = 1

            logger.info('Finished - ' + sdir)

        sys.exit(intRet)