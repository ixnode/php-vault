# Manage environments

## Via command line

### Export keys to environment variables

```bash
$ export PUBLIC_KEY=$(cat .keys/public.key)
```

or

```bash
$ export PRIVATE_KEY=$(cat .keys/private.key)
```

### List keys

```bash
$ printenv | grep "_KEY="
PUBLIC_KEY=...
```

or

```bash
$ printenv | grep "_KEY="
PRIVATE_KEY=...
```

### Delete the exported environments

```bash
$ unset PUBLIC_KEY
```

or

```bash
$ unset PRIVATE_KEY
```

