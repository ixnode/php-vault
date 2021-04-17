# PHPVault
PHPVault creates, reads and builds `.env` environment files. The corresponding values are encrypted with a
public key and decrypted with a private key. Private keys are only available on the production system.
Public keys are available on other systems. Ideal for allowing a secure deployment process.

## On development system

### Generate keys

```bash
$ bin/php-vault generate-keys --persist

The key pair is written to folder ".keys"
```

* **Attention!**:
	* Keep the private key safe for the productive systems.
	* Use the public key on development and local systems.



### Create environment file

* Use public key

```bash
$ bin/php-vault set .env.enc USER secret.user "DB Configs" --public-key --create
$ bin/php-vault set .env.enc PASS secret.pass --public-key
$ bin/php-vault set .env.enc HOST secret.host --public-key
$ bin/php-vault set .env.enc NAME secret.name --public-key
```

### Display the environment file

* Use public key

```bash
$ bin/php-vault display .env.enc --load-encrypted --public-key
...
```

## On production system

### Export the private key to environment variables

### Display an encrypted file

* Use private key

```bash
$ bin/php-vault display .env.enc --load-encrypted --display-decrypted --private-key
+------+-------------+-------------+
| Key  | Value       | Description |
+------+-------------+-------------+
| USER | secret.user | DB Configs  |
| PASS | secret.pass |             |
| HOST | secret.host |             |
| NAME | secret.name |             |
+------+-------------+-------------+
```

### Decrypt encrypted file

* Use private key

```bash
$ bin/php-vault decrypt-file .env.enc --private-key

The file was successfully written to ".env".
```

### Display the decrypted file

* Use private key

```bash
$ bin/php-vault display .env --display-decrypted --private-key
+------+-------------+-------------+
| Key  | Value       | Description |
+------+-------------+-------------+
| USER | secret.user | DB Configs  |
| PASS | secret.pass |             |
| HOST | secret.host |             |
| NAME | secret.name |             |
+------+-------------+-------------+
```

