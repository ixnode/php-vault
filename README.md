# PHPVault

## On development system

### Generate keys

```bash
$ bin/php-vault generate-keys

Name         | Key
--------------------------------------------------------------------------
Private Key  | IGQXjiqwEdKI8eiLVYI+dK32E1JNNAtCKWG2kjgjPJU=
Public Key   | puNWWBXa9++lH6v5sSbc8x4XGzbCArM1A2QoNWdlQXM=
```

* **Attention!**:
	* Keep the private key safe for the productive system.
	* Use the public key on the development system.

### Export the public key to environment variables

```bash
$ export PUBLIC_KEY=$(cat examples/public.key)
```

### If needed: Delete the exported environment

```bash
$ unset PUBLIC_KEY
```

### Create raw environment file

```bash
$ vi env
```

```bash
# DB values
USER=secret.user
PASS=secret.pass
HOST=secret.host
NAME=secret.name
```

### Encrypt environment file

```bash
$ bin/php-vault encrypt-file .env
```

```bash
$ cat .env.enc
# WyJ0WW5QcVp1TDNKUUE5OGtzd1BcLzIzVkdHMWttWkM5dVUiLCI3UVp6cEZXXC82aWNCU1ltb1dDVm54VHh5VUk5amRLbUVVUT09Il0=
USER="WyJUU21ocFg2XC9qQ3hqSVAzd2RkeVNmNTFDYlJIMGU1VG4iLCJ0cmxwbnFleFFiemxwOWZ4cHFXRFwvbm9jRVZFRGl6SVhSa2xiIl0="
PASS="WyJsXC9KODRcLzF5S1lNQ011eGFVQmNpOHFNK09Hcmp4c1FhIiwiWnlsTnRJdzNKcHNTZGViZTJ3UCswSDltRmdmNmdcL1oySW82VSJd"
HOST="WyIyVG1sRWx1bXp5K2RpemNXZnJyOVo1bzZZZXd0cTM4cCIsIlB1Vmo2UHBGWk10XC9mQ3BPVWNXVCtIa2RtSDI5T0FcL1dJMVFMIl0="
NAME="WyJ0U2hRMUJ1RmF6KzZyOElLZkxwekN0bmcwZ1RCS1FBMSIsIklKWUJzc29Yb01LYUo0blRhUUpXSmR3VHhna3dyakVJTHJJdSJd"
```

### Adds values to encrypted file

```bash
$ bin/php-vault set .env.enc PORT 3307 Description
```

### Displays the encrypted file

```bash
$ bin/php-vault display --env-file .env.enc --load-encrypted
```


## On production system

### Export the private key to environment variables

```bash
$ export PRIVATE_KEY=$(cat examples/private.key)
```

### Displays an encrypted file

```bash
$ bin/php-vault display --env-file .env.enc --load-encrypted --display-decrypted
```

### Decrypt encrypted file

```bash
$ bin/php-vault decrypt-file .env.test.enc
```
