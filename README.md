
## What is Vaulty

Vaulty is an open-source secrets manager. The project was inspired by AWS Secret Manager and has a tint of MongoDB. Secret managers provide a way to securely retrieve passwords, certificates, tokens, etc., which replaces hard-coding your "secrets" in your programs. You can learn more about secret managers here: [AWS Secret Manager Intro](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html).

Please note that if you have or believe you have found a **security issue**, please open an issue or disclose it by contacting me at me@vex.rs.

## Encryption Used

* The secrets are encrypted with RSA 4096 with AES 256 GCM.
* The access key authentication is done with ECDSA 256.
* The passwords are hashes with Argon2.

## Vaulty

#### Command Arguments

Currently, there's only one optional argument `--config [config location]` i.e. `vaulty --config /var/vaulty.yml`, to specify the config file. The default behavior is to open **config.yml** from the current directory.

#### Config

Before you run the **vaulty** you first need to setup the config file. Template of the config file:

```
node_name: Vaulty
log:
  filename: vault.log
db:
  location: database.bin
secrets:
  rsa_private_key:
  rsa_public_key:
  aes_key:
  aes_iv:
access_keys:
  signing_key:
  verifying_key:
  delay_unsuccessful_attempts_millis: 5000
  acces_key_length: 20
  secret_access_key_length: 40
users:
  delay_unsuccessful_attempts_millis: 5000
server:
  listen_address: 0.0.0.0
  listen_port: 8080
  tls:
    certificate:
    key:
```

General settings:
* **node_name** - Allows you to name your vaulty, when you log in via the CLI you will see the name as identifier.
* **db.database** - Sets the location of the database.
* **users.delay_unsuccessful_attempts_millis** - How much to delay in milliseconds on an unsuccessful login attempt.

Log settings (Optional):
* **log.filename** - You can set where to store the logs, if it's not present it will not sav any logs.

Secrets settings[^1]:
* **secrets.rsa_private_key** - RSA 4096 bit private key.
* **secrets.rsa_public_key** - RSA 4096 bit public key.
* **secrets.aes_key** - AES 32 bytes key.
* **secrets.aes_iv** - AES 12 bytes key.

Access key settings[^2]:
* **access_keys.signing_key** - ECDSA 256 private key.
* **access_keys.verifying_key** - ECDSA 256 public key.
* **access_keys.delay_unsuccessful_attempts_millis** - How much to delay in milliseconds on an unsuccessful attempt.
* **access_keys.acces_key_length** - When generating access keys, how long to be.
* **access_keys.secret_access_key_length** - When generating access keys, how long the secret access key be.

Server settings:
* **server.listen_address** - The address to which the server will listen.
* **server.listen_port** - The port to which the server will listen.

Server's TLS settings (Optional)[^3]:
* **server.tls.certificate** - TLS certificate.
* **server.tls.key** - TLS key.

#### API

You can use basic HTTP (like curl) to access the secrets with an access key. To authenticate you must include the following header in the HTTP request `Authorization: VAULTY [ACCESS KEY]:[SECRET ACCESS KEY`, example: `Authorization VAULTY tHeeFQ8HtyrVTU51YEBj:U9r7j3rJMHrU6A0hRCkV1VrdEmL1cFc7R2r0HFtU`

| Method | URL | w |
| - | - | - |
| GET | /[VAULT] | Lists all secrets in the vault |
| GET | /[VAULT]/[SECRET NAME] | Retrieve a secret |
| DELETE | /[VAULT]/[SECRET NAME] | Delete a secret |
| POST/PUT | /[VAULT]/[SECRET NAME] | Insert a secret |

#### Notes

When **vaulty** initializes (creates in this sense) the database, it will create a user named **root** with a random password, and the password will be displayed in the logs and STDOUT appropriately, the security group of this user will be **127.0.0.1/32** which means you can login only from the machine where **vaulty** is running.

## Vaulty-CLI

#### Connecting

The connection string is how you tell the CLI where to connect. The schema is ``vaulty://[username]:[password]@[IP or FQDN]:[PORT]/[PARAMS]``. The params can be **tls** to enable TLS connections, and **tlsAllowInvalidCerts** to allow self-signed certificates.

Example of a connection string: ``vaulty-cli "vaulty://root:JRrGtFHTKrJoQ1TBTya2@localhost:8080/?tls=true&tlsAllowInvalidCerts=true"``

Note that if the port is not specified it will use port **80** for non-TLS connections, for TLS connections it will use port **443**.

#### Command Line

The arguments follow a flow style YAML, for example to create an Admin user you have to run:

```
user.insert({ username: "root", role: "Admin", sg: ["0.0.0.0/0"] })
```

##### User Roles

* Admin
* User

##### Access Key Permissions

* ListSecrets
* DeleteSecrets
* CreateSecrets
* DecryptSecrets

##### Commands
* **user.insert([arg])** - Inserts a user. Arguments:
  * **username** - User's name.
  * **password** - (Optional) Specify the password, if not set you will be prompted for one.
  * **role** - The role of the user.
  * **sg** - Array of security groups.
* **user.list** - List all users.
* **user.[username].find** - Find a specific user.
* **user.[username].delete** - Delete a specific user.
* **user.[username].changePassword([arg])** - Change user's password. Arguments:
  * **password** - (Optional) Specify the password, if not set you will be prompted for one.
* **user.[username].changeSg([arg])** - Change user's security group. Arguments:
  * **sg** - Array of security groups.
* **user.[username].promote** - Promote user to Admin.
* **user.[username].demote** - Demote user to User.
* **vault.list** - List all vaults.
* **vault.[vault].find** - Find a specific vault.
* **vault.[vault].delete** - Delete a vault, note it will delete all access keys and secrets in it.
* **access.[vault].list** - List the vault's access keys.
* **access.[vault].[access key].find** - Find specific access key.
* **access.[vault].insert([arg])** - Insert an access key in a vault. Arguments:
  * **permission** - Array of permissions.
  * **sg** - Array of security groups.
* **access.[vault].[access key].delete** - Delete specific access key.
* **access.[vault].[access key].changePermission([arg])** - Update access key's permission. Arguments:
  * **permission** - Array of permissions.
* **access.[vault].[access key].changeSg([arg])** - Update access key's security group. Arguments:
  * **sg** - Array of security groups.
* **secret.[vault].list** - List the vault's secrets.
* **secret.[vault].[secret name].insert([arg])** - Insert a secret. The argument must be one of these:
  * **text** - text.
  * **binary** - base64 encoded binary data.
  * **file** - insert a file.
* **secret.[vault].[secret name].find** - Find a specific secret.
* **secret.[vault].[secret name].delete** - Delete a specific secret.

#### Notes
When logging in, if you don't specify a username or password, or even both, you will be prompted for them.

To create a vault, you need to insert a secret or an access key; either one will create the vault.

[^1]: To generate the keys, you have to run the script in **secrets/gen-secrets-key.sh**, or **secrets/gen-secrets-key.ps1** for Windows, it will produce **RSA private key**, **RSA public key**, **AES key**, and **AES IV**.

[^2]: To generate the keys, you have to run the script in **secrets/gen-access-keys.sh**, or **secrets/gen-access-keys.ps1** for Windows, it will produce **ECDSA private key** and **ECDSA public key**.

[^3]: To generate the keys, you have to run the script in **secrets/gen-server-cert.sh**, or **secrets/gen-server-cert.ps1** for Windows, it will produce a **certificate** and a **key**.
