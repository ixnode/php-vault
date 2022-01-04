# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Releases

### [1.1.0] - 2022-01-04

* [#3](https://github.com/ixnode/php-vault/issues/3) - Add Semantic Versioning 2.0.0

### [v1.0.7] - 2021-04-28

* Private and public key version 2 with verification hash

### [v1.0.6] - 2021-04-25

* Add prefix PHPVAULT_ to written system environment variables

### [v1.0.5] - 2021-04-25

* Fix PHPStan static code analysis on level 8 (max)

### [v1.0.4] - 2021-04-23

* Fix $_SERVER, $_ENV and putenv writer

### [v1.0.3] - 2021-04-23

* Reading and outputting the same string types no longer requires a key

### [v1.0.2] - 2021-04-23

* Writes vault to $_SERVER, $_ENV and putenv

### [v1.0.1] - 2021-04-18

* Keep PHP 7.4 compatibility

### [v1.0.0] - 2021-04-18

* First productive version

## Add new version

```bash
# checkout master branch
$ git checkout master && git pull

# add new version
$ echo "v1.1.0" > VERSION

# Change changelog
$ vi CHANGELOG.md

# Push new version
$ git add CHANGELOG.md VERSION && git commit -m "Add version $(cat VERSION)" && git push

# Tag and push new version
$ git tag -a "v$(cat VERSION)" -m "Version $(cat VERSION)" && git push origin "$(cat VERSION)"
```
