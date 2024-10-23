# Object Validator: Integrity validation of object data

<div align="center">

<img src="https://www.walacor.com/wp-content/uploads/2022/09/Walacor_Logo_Tag.png" width="300" />

[![License Apache 2.0][badge-license]][license]
[![Walacor (1100127456347832400)](https://img.shields.io/badge/My-Discord-%235865F2.svg?label=Walacor)](https://discord.gg/BaEWpsg8Yc)
[![Walacor (1100127456347832400)](https://img.shields.io/static/v1?label=Walacor&message=LinkedIn&color=blue)](https://www.linkedin.com/company/walacor/)
[![Walacor (1100127456347832400)](https://img.shields.io/static/v1?label=Walacor&message=Website&color)](https://www.walacor.com/product/)

</div>

[badge-license]: https://img.shields.io/badge/license-Apache2-green.svg?dummy
[license]: https://github.com/walacor/objectvalidation/blob/main/LICENSE

Object Validator is a utility program that uses cryptography and Walacor's immutable data platform to  ensure objects/files have not been manipulated or tampered with over time.

Due to the nature of hashes/signatures if any object/file that was used to build the original hash changes, the entire hash will change.  Doing this at a directory level is an effective way of ensuring the integrity of objects/file without having to manage a large number of hashes.

The workflow is like this:

1. Generate hashes of object data (Either Filesystem or S3)
   * All objects/files within a dir, and all sub dirs, are streamed to a single hash
2. Write those hashes to a Walacor instance
   * At a later time Validate the hashes (Either Filesystem or S3)
3. Recreated the hash from the source and ensure nothing has changed

# Some Specifics

There are 2 hashes that get created:

* The directory hash, the name of the top level dir
  * This is used as a key to find the content hash
* The hash of the directories contents
  * A single hash that represents all of the files within the directory

# Installation

## Running in a container

It is recommended running ObjectValidator in a container to ensure isolation and have the ability to use a dedicated secure enclave.

## Container setup

```sh
# Use Python 3.11 as base image
FROM python:bullseye

# Copy the current directory contents into the container at /app
ADD ObjectValidator.py .
ADD requirements.txt .

# Install the required libraries
RUN pip install “./requirements.txt

# Command to run the Python script
CMD [“python”, “./ObjectValidator.py”] 
```
## Walacor Instance

### Why use Walacor?

> Ensuring the integrity of data eventually comes down to a single component that is the linchpin of trust.  For most solutions this requires reliance on a complex stack of integrated technologies.  Walacor is a single software solution who's sole mission is to ensure data integrity...What you put in is exactly what you get out, and it can be proven. [Read More](https://www.walacor.com)

You need access to a running Walacor instance with Admin user credentials. I you do not have a Walacor instance you can create one for a minimal fee on the cloud services. Detailed installation instructions are also provided.

[[AWS Marketplace]](https://aws.amazon.com/marketplace/pp/prodview-n6yuvr2g44wpo)
[[AWS install Doc]](https://admindoc.walacor.com/admin-documentation/latest/aws-marketplace-server-instance-installation)

[[Azure Marketplace]](https://azuremarketplace.microsoft.com/en-us/marketplace/apps?search=walacor)
[[Azure install Doc]](https://admindoc.walacor.com/admin-documentation/latest/azure-server-instance-installation)

## Getting Started

The program takes positional parameters:

* 1 - Mode (1=make sig, 2=validate sig) I.E. 1
* 2 - Source (1=Local File, 2=S3) I.E. 1
* 3 - Walacor API endpoint root I.E. *Walacor URL, need /api and no trailing slash*
* 4 - Walacor API user I.E. username
* 5 - Walacor API password I.E. XXXX
* 6 - Log File Name I.E. S3DirHash_Log.txt
* 7 - Log Level (10,20,30,40,50) (20 is recommended)
* 8 - Root (the root location to work from) I.E. /*Some Directory*
* 9 - Specific Dir I.E. A specific dir inside of #8 the root, no leading or tailing slashed
* 10 - s3 endpoint I.E. If not a standard S3 endpoint (Might not be necessary)
* 11 - s3 Access Key
* 12 - s3 Secret Key
* 13 - s3 region I.E. us-west-1
* 14 - s3 bucket I.E. *S3 Bucket Name*

### Examples of command line

Generate Signatures from filesystem
```sh
S3_Validation.py 1 1 https://mywalacor.myplace.com/api WalacorUser WalacorPassword LogFile.txt 20 RootDir "" 
```

Validate Signatures from filesystem

```sh
S3_Validation.py 2 1 https://mywalacor.myplace.com/api WalacorUser WalacorPassword LogFile.txt 20 RootDir ""
```

Generate Signatures from S3 compatible source

```sh
S3_Validation.py 1 2 https://mywalacor.myplace.com/api WalacorUser WalacorPassword LogFile.txt 20 RootDir "" "" AWSAccessKey AWSSecretKey us-west-1 s3Bucket
```

Validate Signatures from S3 compatible source

```sh
S3_Validation.py 2 2 https://mywalacor.myplace.com/api WalacorUser WalacorPassword LogFile.txt 20 RootDir "" "" AWSAccessKey AWSSecretKey us-west-1 s3Bucket
```

# Potential enhancements

- [ ] Make the directory hash more resilient to collisions
- [ ] Verify container setup
- [ ] Make the hashing algorithm a setting
- [ ] Enable the 8th parameter (root)