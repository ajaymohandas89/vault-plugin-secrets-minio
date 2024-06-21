# vault-plugin-secrets-minio

MinIO offers high-performance, S3 compatible object storage. Native to Kubernetes, MinIO is the only object storage suite available on every public cloud, every Kubernetes distribution, the private cloud and the edge. Vault supports 3 types of plugins; auth methods, secret engines, and database plugins.

This is a secret engine plugin that combines [HashiCorp Vault](https://www.vaultproject.io/) and [Minio object storage](https://min.io/) server. Vault Minio Plugin can generate dynamic secret credentials used to access oss/minio server and avoid manual generation of credentials. 

Project is also forked from https://github.com/kula/vault-plugin-secrets-minio. Thanks to Thomas L. Kula, providing a base for this project

## Pre-requisites

1. Install vault, https://developer.hashicorp.com/vault/docs/install 
2. Build plugin as mentioned here https://developer.hashicorp.com/vault/tutorials/app-integration/plugin-backends
3. Register and enable the plugin

## How plugin generates dynamic credential?

A) Generating dynamic credentials when sts is set to true

1. Retrieves role details

2. Calculates the ttl for the sts credentials

3. Using minio admin credentials and configuration endpoint, we create user static credentials and store in the vault's persistance storage

4. Using user static credentials we generate STS credentials

5. Returns the STS credentials

B) When flag for sts is set to false (default value is false), following steps occur

1. Retrieves role details
2. Retrieve user credentials stored in vault storage, if present

3. If calling this API for the first time, then below are executed

    - Generate secret access key using uuid.GenerateRandomBytes and encoding it using bas64

    - Access key is the combination of user_name_prefix (optional) and request id

    - Create a user using minio admin access key id and secret access key and add them in minio server

    - Attach a policy to that user

    - Store these information in a map where key is role name and value are the static credentials generated

    - Store the map in vault storage

## Usage

Once the plugin is registered with your vault instance, you can enable it
on a particular path and for a each vault namespace:

    $ vault secrets enable 	-namespace=<vault-namespace> -path=<path> -plugin-name=vault-plugin-secrets-minio -description="Instance of the Minio plugin plugin" minio
----
### Configuration

In order to configure the plugin instance, you must supply it with your Minio
endpoint, the access key ID, and the secret access key for the Minio initial
user. 

    $ vault write <path>/config/root
        -namespace=<vault-namespace>
        endpoint=<minio ip>:<minio port>
        accessKeyId=<minio admin access key ID> 
        secretAccessKey=<minio admin secret access key>
        useSSL=<true|false>

You can read the current configuration:

    $ vault read -namespace=<vault-namespace> <path>/config/root

You can delete the current configuration:

    $ vault delete -namespace=<vault-namespace> <path>/config/root
----
### Roles

Before you can issue keys, you must define a role. A role defines the 
policy which will be applied to the newly created user.

    $ Static Credential Role

    vault write -namespace=<vault-namespace> <path>/roles/example-role \
        policy_name=<existing minio policy name>
        user_name_prefix=<user name prefix>
        credential_type=static

    STS Credential Role

    vault write -namespace=<vault-namespace> <path>/roles/example-role \
        policy_name=<existing minio policy name>
        policy_document=<policy in json format>
        credential_type=sts
        max_sts_ttl=time

**_NOTE:_** 
> `<user name prefix>` is prefixed to the Vault request id for a key request,
and defaults to an empty string. Having the Vault request id as the 
latter part of the name allows you to trace the key issuer via the Vault
audit log. You may also optionally supply a `max_sts_ttl`
which will apply to the sts credentials generated by this role.
> Default values for `max_sts_ttl` set is 15 minustes

Returns the configuration for a particular role. 

    $ vault read -namespace=<vault-namespace> <path>/roles/example-role

Lists all configured roles.

    $ vault list -namespace=<vault-namespace> <path>/roles

Delete configured roles.

    $ vault delete -namespace=<vault-namespace> <path>/roles/example-role

---
### Provisioning keys

Generating User Static Credential

    $ vault read <path>/creds/example-role

Generating STS Credential

    $ vault write <path>/creds/example-role ttl=<time in seconds>
___
## Unit Test
To run the unit tests for this project run below command
    
    $ go test -coverprofile=coverage.out

To view the coverage output in html format

    $ go tool cover -html=coverage.out

---
## References

[Vault](https://www.vaultproject.io/)

[Secrets Made Easy](https://blog.min.io/minio-and-hashicorp-vault/)

[MinIO](https://min.io/)