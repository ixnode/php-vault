# PHPVault

PHPVault is a PHP library that can create, read, encrypt and decrypt environment files (so-called dotenv files). For
example is `.env` a plain file, `.env.enc` an encrypted file, etc. Within your project you can automatically load these
encrypted  environment variables from `.env.enc` into `getenv()`, `$_ENV` and `$_SERVER`. The corresponding key-value
pairs within these dotenv files are encrypted and decrypted using an asymmetric encryption method
([Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)). Private keys are only available
on productive systems for decrypting dotenv values. The public key, on the other hand, can be safely checked into
the repository and is used everywhere to encrypt new values.

The strict separation of configuration and code is a fundamental principle of software development and is based on the
[The Twelve-Factor App](https://www.12factor.net/config) methodology. One way to do this is to store these data into
separate configuration files such as the dotenv files mentioned above. These are mostly unencrypted, but usually
contain very *sensitive* data such as database access and API keys. They must therefore never be checked into the code
repository! Since these are usually files within the project, there is still a risk that this could happen by mistake.

The PHPVault approach preserves the principle of separation and goes one step further: It encrypts plain dotenv
files and allows them to be checked into the code repository. To decrypt and use the data on a productive system,
simply exchange the private key. This approach is great for providing secure and automated deployment processes
([CI/CD](https://en.wikipedia.org/wiki/CI/CD), etc.).

To start simply run:

```bash
$ composer require ixnode/php-vault
```

This requires [Composer](https://getcomposer.org/), a dependency manager for PHP.

## Command line command `vendor/bin/php-vault`

The basis of all operations is the command line tool `vendor/bin/php-vault`.  Help can be displayed at any time:

```bash
$ vendor/bin/php-vault --help
PHPVault command line interpreter.
PHPVault, version v1.0.5

Commands:
  decrypt-file  df    Decrypts a given file. Requires a private key.
  display       d     Displays the environment variables from given file.
  display-env   de    Displays the environment variables from server.
  encrypt-file  ef    Encrypts a given file. Requires a public key.
  generate-keys gk    Generates and displays a private and public key.
  info          i     Shows information.
  set           s     Sets or updates a new variable. Needs a public key.

Run `<command> --help` for specific help
```

```bash
$ vendor/bin/php-vault --version
v1.0.5
```

## On development system

Usually, you need the *public* key in this environment. Examples can be found below. There are several
[ways](docs/ENVIRONMENT.md) to pass the public key to the `php-vault` interpreter. In the following,
the key is loaded from the `.keys` directory (`--public-key`).

### Generate keys

```bash
$ vendor/bin/php-vault generate-keys --persist

The key pair is written to folder ".keys"

Never add the private key to the repository!
```

* **Attention!**:
	* Keep the private key safe for the productive systems (`.keys/private.key`).
	    * Delete the private key file `.keys/private.key` if you have saved it and submitted it to the admin for the productive system.
	* Use the public key on development and local systems (`.keys/public.key`).

### Create environment file

* Add key-value pair `DB_USER=secret.user` with description `"DB Configs"`
* Add key-value pair `DB_PASS=secret.pass`
* Add key-value pair `DB_HOST=secret.host`
* Add key-value pair `DB_NAME=secret.name`
* Use public key (`--public-key` → read from `.keys/public.key`).

```bash
# Create file .env.enc
$ vendor/bin/php-vault set .env.enc DB_USER secret.user "DB Configs" --public-key --create
# Adds values to .env.enc
$ vendor/bin/php-vault set .env.enc DB_PASS secret.pass --public-key
$ vendor/bin/php-vault set .env.enc DB_HOST secret.host --public-key
$ vendor/bin/php-vault set .env.enc DB_NAME secret.name --public-key
```

### Display the environment file

* The contents displayed are encrypted.
* Do not need any key.

```bash
$ vendor/bin/php-vault display .env.enc --load-encrypted
...
```

## On production system

Usually, you need the *private* key in this environment. Examples can be found below. There are several
[ways](docs/ENVIRONMENT.md) to pass the private key to the `php-vault` interpreter. In the following,
the key is loaded from the `.keys` directory (`--private-key`).

### Display an encrypted file

* Use private key (`--private-key` → read from `.keys/private.key`).

```bash
$ vendor/bin/php-vault display .env.enc --load-encrypted --display-decrypted --private-key
+---------+-------------+-------------+
| Key     | Value       | Description |
+---------+-------------+-------------+
| DB_USER | secret.user | DB Configs  |
| DB_PASS | secret.pass |             |
| DB_HOST | secret.host |             |
| DB_NAME | secret.name |             |
+---------+-------------+-------------+
```

### Decrypt an encrypted file

* Never add the produced decrypted file `.env` to the repository!
* Use private key (`--private-key` → load from `.keys/private.key`).

```bash
$ vendor/bin/php-vault decrypt-file .env.enc --private-key

The file was successfully written to ".env".
```

### Display the decrypted file without encryption

* Do not need any key.

```bash
$ vendor/bin/php-vault display .env --display-decrypted
+------+-------------+-------------+
| Key  | Value       | Description |
+------+-------------+-------------+
| USER | secret.user | DB Configs  |
| PASS | secret.pass |             |
| HOST | secret.host |             |
| NAME | secret.name |             |
+------+-------------+-------------+
```

## Using the PHPVault class

### Load the private key from a given file

```php
<?php

require 'vendor/autoload.php';

use Ixnode\PhpVault\PHPVault;

/* Path to private key and .env.enc */
$pathToPrivateKey = __DIR__.'/.keys/private.key';
$pathToEncryptedEnv = __DIR__.'/.env.enc';

/* - Initiate PHPVault Core.
 * - Load private key.
 * - Load the encrypted env file.
 */
$phpVault = new PHPVault();
$phpVault->loadPrivateKeyFromFile($pathToPrivateKey);
$phpVault->importEncryptedEnvFile($pathToEncryptedEnv);

/* Usage */
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');
$dbHost = getenv('DB_HOST');
$dbName = getenv('DB_NAME');
```

### Load the private key from the server environment variable `PRIVATE_KEY`

For options to set the environment variable, see [here](docs/ENVIRONMENT.md).

```php
<?php

require 'vendor/autoload.php';

use Ixnode\PhpVault\PHPVault;

/* Path to private key and .env.enc */
$pathToEncryptedEnv = __DIR__.'/.env.enc';

/* - Initiate PHPVault Core and use the PRIVATE_KEY environment variable.
 * - Load the encrypted env file.
 */
$phpVault = new PHPVault();
$phpVault->importEncryptedEnvFile($pathToEncryptedEnv);

/* Usage */
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');
$dbHost = getenv('DB_HOST');
$dbName = getenv('DB_NAME');
```

## Security

If you discover a security vulnerability within this package, please send an email to Björn Hempel at
bjoern@hempel.li. All security vulnerabilities will be promptly addressed. You may view our full
security policy [here](https://github.com/ixnode/php-vault/security/policy).

## License

PHPVault is licensed under [MIT](https://github.com/ixnode/php-vault/blob/master/LICENSE).
