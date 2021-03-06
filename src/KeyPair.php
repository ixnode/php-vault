<?php declare(strict_types=1);

/*
 * MIT License
 *
 * Copyright (c) 2021 Björn Hempel <bjoern@hempel.li>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Ixnode\PhpVault;

use Exception;
use Ixnode\PhpVault\Exception\PHPVaultPrivateKeyLoadedException;
use Ixnode\PhpVault\Exception\PHPVaultPublicKeyLoadedException;
use Ixnode\PhpVault\Exception\PHPVaultUnknownKeyVersionException;
use SodiumException;

class KeyPair
{
    private PHPVault $phpVaultCore;

    private ?string $privateKey = null;

    private ?string $publicKey = null;

    protected ?string $loadedFromSource = null;

    protected ?string $loadedFromPath = null;

    protected ?string $loadedFromEnvironment = null;

    protected ?string $loadedFromVersion = null;

    protected int $loadedSize = 0;

    const SERVER_PUBLIC_KEY_NAME = 'PUBLIC_KEY';

    const SERVER_PRIVATE_KEY_NAME = 'PRIVATE_KEY';

    const LOADED_FROM_FILE = 'FILE';

    const LOADED_FROM_ENVIRONMENT = 'ENVIRONMENT';

    const LOADED_FROM_PASSED_STRING = 'PASSED_STRING';

    const LOADED_FROM_RANDOM_GENERATOR = 'RANDOM_GENERATOR';

    const VERSION_1 = 'v1';

    const VERSION_2 = 'v2';

    const VERSION_UNKNOWN = null;

    const VERSION_UNKNOWN_NAME = 'unknown';

    /**
     * KeyPair constructor.
     *
     * @param PHPVault $phpVaultCore
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @throws SodiumException
     */
    public function __construct(PHPVault $phpVaultCore, bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null)
    {
        $this->phpVaultCore = $phpVaultCore;

        /* Renew key if given. */
        $this->init($forceCreateNew, $privateKey, $publicKey);
    }

    /**
     * Deletes the key pair.
     *
     * @return void
     * @throws Exception
     */
    protected function deleteKeyPair(): void
    {
        $this->setPrivateKey(null);
        $this->setPublicKey(null);
        $this->phpVaultCore->setMode(Mode::MODE_NONE);
        $this->loadedFromSource = null;
        $this->loadedFromPath = null;
        $this->loadedFromEnvironment = null;
        $this->loadedFromVersion = null;
    }

    /**
     * Sets private key pair from given array.
     *
     * @param array{'private': ?string, 'private-hashed': ?string, 'public': string, 'public-hashed': string, 'loaded-version': ?string, 'loaded-size': int} $keyPair
     * @param int $mode
     * @param string $loadedFromSource
     * @param string|null $loadedFromEnvironment
     * @return void
     * @throws Exception
     */
    protected function setKeyPair(array $keyPair, int $mode, string $loadedFromSource, string $loadedFromEnvironment = null): void
    {
        /* Set private and public key. */
        $this->setPrivateKey($keyPair['private']);
        $this->setPublicKey($keyPair['public']);

        /* Set mode, loaded from source and environment */
        $this->phpVaultCore->setMode($mode);
        $this->loadedFromSource = $loadedFromSource;
        $this->loadedFromEnvironment = $loadedFromEnvironment;
        $this->loadedFromVersion = $keyPair['loaded-version'];
        $this->loadedSize = $keyPair['loaded-size'];
    }

    /**
     * Returns the base64 encoded private key string.
     *
     * @return string|null
     */
    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    /**
     * Sets the base64 encoded private key string.
     *
     * @param string|null $privateKey
     * @return void
     */
    public function setPrivateKey(?string $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Returns the length of base64 encoded private key string.
     *
     * @return int
     */
    public function getPrivateKeyLength(): int
    {
        if ($this->privateKey === null) {
            return 0;
        }

        return strlen($this->privateKey);
    }

    /**
     * Returns a private key hash.
     *
     * @return string|null
     */
    public function getPrivateKeyHash(): ?string
    {
        if ($this->privateKey === null) {
            return null;
        }

        return md5($this->privateKey);
    }

    /**
     * Returns a private key hash.
     *
     * @return string|null
     */
    public function getPrivateKeyCombined(): ?string
    {
        $json = json_encode(
            array(
                $this->getPrivateKey(),
                $this->getPublicKeyHash(),
            )
        );

        return $json === false ? null : base64_encode($json);
    }

    /**
     * Returns the private key according to given version.
     *
     * @param string $version
     * @return ?string
     * @throws PHPVaultUnknownKeyVersionException
     */
    public function getPrivateKeyByVersion(string $version = self::VERSION_1): ?string
    {
        switch ($version) {
            case self::VERSION_1:
                return $this->getPrivateKey();

            case self::VERSION_2:
                return $this->getPrivateKeyCombined();

            default:
                throw new PHPVaultUnknownKeyVersionException();
        }
    }

    /**
     * Returns the base64 decoded public string.
     *
     * @return string|null
     */
    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    /**
     * Sets the base64 decoded public string.
     *
     * @param string|null $publicKey
     * @return void
     */
    public function setPublicKey(?string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    /**
     * Returns the length of base64 encoded public key string.
     *
     * @return int
     */
    public function getPublicKeyLength(): int
    {
        if ($this->publicKey === null) {
            return 0;
        }

        return strlen($this->publicKey);
    }

    /**
     * Returns a private key hash.
     *
     * @return string|null
     */
    public function getPublicKeyHash(): ?string
    {
        if ($this->publicKey === null) {
            return null;
        }

        return md5($this->publicKey);
    }

    /**
     * Returns a private key hash.
     *
     * @return string|null
     */
    public function getPublicKeyCombined(): ?string
    {
        $json = json_encode(
            array(
                $this->getPublicKey(),
                $this->getPrivateKeyHash(),
            )
        );

        return $json === false ? null : base64_encode($json);
    }

    /**
     * Returns the public key according to given version.
     *
     * @param string $version
     * @return ?string
     * @throws PHPVaultUnknownKeyVersionException
     */
    public function getPublicKeyByVersion(string $version = self::VERSION_1): ?string
    {
        switch ($version) {
            case self::VERSION_1:
                return $this->getPublicKey();

            case self::VERSION_2:
                return $this->getPublicKeyCombined();

            default:
                throw new PHPVaultUnknownKeyVersionException();
        }
    }

    /**
     * Returns the location where the key was loaded from (source).
     *
     * @return string|null
     */
    public function loadedFromSource(): ?string
    {
        return $this->loadedFromSource;
    }

    /**
     * Returns the location where the key was loaded from (path).
     *
     * @return string|null
     */
    public function loadedFromPath(): ?string
    {
        return $this->loadedFromPath;
    }

    /**
     * Returns the location where the key was loaded from (environment).
     *
     * @return string|null
     */
    public function loadedFromEnvironment(): ?string
    {
        return $this->loadedFromEnvironment;
    }

    /**
     * Returns the version with which the key was loaded.
     *
     * @return string|null
     */
    public function loadedFromVersion(): ?string
    {
        return $this->loadedFromVersion;
    }

    /**
     * Returns the loaded key size.
     *
     * @return int
     */
    public function loadedSize(): int
    {
        return $this->loadedSize;
    }


    /**
     * Returns the name of version (including unknown).
     *
     * @return string
     */
    public function getVersionName(): string
    {
        if ($this->loadedFromVersion === null) {
            return self::VERSION_UNKNOWN_NAME;
        }

        return $this->loadedFromVersion;
    }

    /**
     * Returns that no key was loaded.
     *
     * @return bool
     */
    public function noKeyIsLoaded(): bool
    {
        return $this->loadedFromSource === null;
    }

    /**
     * Returns that a key was loaded.
     *
     * @return bool
     */
    public function keyIsLoaded(): bool
    {
        return $this->loadedFromSource !== null;
    }

    /**
     * Init the KeyPair class.
     *
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @return void
     * @throws SodiumException
     */
    public function init(bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null): void
    {
        $this->renew($forceCreateNew, $privateKey, $publicKey, false);
    }

    /**
     * Renews the saved public private key.
     *
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @param bool $throwException
     * @return bool
     * @throws SodiumException
     * @throws Exception
     */
    public function renew(bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null, bool $throwException = true): bool
    {
        /* Delete key pair. */
        $this->deleteKeyPair();

        /* Force create new key pair */
        if ($forceCreateNew) {
            $this->setKeyPair(
                self::getNewPair(),
                Mode::MODE_DECRYPT,
                self::LOADED_FROM_RANDOM_GENERATOR
            );
            return true;
        }


        /* Read private key from input parameter */
        if ($privateKey !== null) {
            $this->setKeyPair(
                self::getPairFromPrivateKey($privateKey),
                Mode::MODE_DECRYPT,
                self::LOADED_FROM_PASSED_STRING
            );
            return true;
        }

        /* Read private key from $_SERVER variable. */
        if (array_key_exists(self::SERVER_PRIVATE_KEY_NAME, $_SERVER)) {
            $this->setKeyPair(
                self::getPairFromPrivateKey($_SERVER[self::SERVER_PRIVATE_KEY_NAME]),
                Mode::MODE_DECRYPT,
                self::LOADED_FROM_ENVIRONMENT,
                self::SERVER_PRIVATE_KEY_NAME
            );
            return true;
        }


        /* Read public key from input parameter */
        if ($publicKey !== null) {
            $this->setKeyPair(
                self::getPairFromPublicKey($publicKey),
                Mode::MODE_ENCRYPT,
                self::LOADED_FROM_PASSED_STRING
            );
            return true;
        }

        /* Read private key from $_SERVER variable. */
        if (array_key_exists(self::SERVER_PUBLIC_KEY_NAME, $_SERVER)) {
            $this->setKeyPair(
                self::getPairFromPublicKey($_SERVER[self::SERVER_PUBLIC_KEY_NAME]),
                Mode::MODE_ENCRYPT,
                self::LOADED_FROM_ENVIRONMENT,
                self::SERVER_PUBLIC_KEY_NAME
            );
            return true;
        }


        /* No key was found. */
        if ($throwException) {
            throw new Exception('No private or public key found.');
        }

        return false;
    }

    /**
     * Checks if a private or public key exists within the environment ($_SERVER).
     *
     * @return bool
     */
    public function keyExistsWithinEnvironment(): bool
    {
        return array_key_exists(self::SERVER_PRIVATE_KEY_NAME, $_SERVER) || array_key_exists(self::SERVER_PUBLIC_KEY_NAME, $_SERVER);
    }

    /**
     * Loads private key from file.
     *
     * @param string $privateKey
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function loadPrivateKeyFromFile(string $privateKey): void
    {
        /* Check that given file exists. */
        if (!file_exists($privateKey)) {
            throw new Exception(sprintf('The given private key "%s" does not exists.', $privateKey));
        }

        /* Load key */
        $privateKeyString = file_get_contents($privateKey);

        /* Check loaded key */
        if ($privateKeyString === false) {
            throw new Exception(sprintf('The given private key "%s" could not be loaded.', $privateKey));
        }

        /* Renew key */
        if ($this->renew(false, $privateKeyString)) {
            $this->loadedFromSource = self::LOADED_FROM_FILE;
            $this->loadedFromPath = $privateKey;
        }
    }

    /**
     * Loads public key from file.
     *
     * @param string $publicKey
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function loadPublicKeyFromFile(string $publicKey): void
    {
        /* Check that given file exists. */
        if (!file_exists($publicKey)) {
            throw new Exception(sprintf('The given public key "%s" does not exists.', $publicKey));
        }

        /* Load key */
        $publicKeyString = file_get_contents($publicKey);

        /* Check loaded key */
        if ($publicKeyString === false) {
            throw new Exception(sprintf('The given public key "%s" could not be loaded.', $publicKey));
        }

        /* Renew key */
        if ($this->renew(false, null, $publicKeyString)) {
            $this->loadedFromSource = self::LOADED_FROM_FILE;
            $this->loadedFromPath = $publicKey;
        }
    }

    /**
     * Returns a new public private key object (static function).
     *
     * @return array{'private': string, 'private-hashed': string, 'public': string, 'public-hashed': string, 'loaded-version': ?string, 'loaded-size': int}
     * @throws SodiumException
     */
    public static function getNewPair(): array
    {
        $keyPair = sodium_crypto_box_keypair();

        $publicKey = base64_encode(sodium_crypto_box_publickey($keyPair));
        $publicKeyHash = md5($publicKey);
        $privateKey = base64_encode(sodium_crypto_box_secretkey($keyPair));
        $privateKeyHash = md5($privateKey);
        $loadedVersion = self::VERSION_UNKNOWN;
        $loadedSize = 0;

        return [
            'public' => $publicKey,
            'public-hashed' => $publicKeyHash,
            'private' => $privateKey,
            'private-hashed' => $privateKeyHash,
            'loaded-version' => $loadedVersion,
            'loaded-size' => $loadedSize,
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded private key (static function).
     *
     * @param string $privateKey
     * @return array{'private': string, 'private-hashed': string, 'public': string, 'public-hashed': string, 'loaded-version': ?string, 'loaded-size': int}
     * @throws SodiumException
     * @throws Exception
     */
    public static function getPairFromPrivateKey(string $privateKey): array
    {
        $privateKeyArray = array();
        $loadedVersion = self::VERSION_1;
        $loadedSize = strlen($privateKey);

        if (self::isJson(base64_decode($privateKey))) {
            $privateKeyArray = json_decode(base64_decode($privateKey));
            $privateKey = $privateKeyArray[0];
        }

        $privateKeyHash = md5($privateKey);
        $publicKey = base64_encode(sodium_crypto_box_publickey_from_secretkey(base64_decode($privateKey)));
        $publicKeyHash = md5($publicKey);

        /* Check hash match. */
        if (count($privateKeyArray) > 1) {
            $loadedVersion = self::VERSION_2;
            if ($publicKeyHash !== $privateKeyArray[1]) {
                throw new PHPVaultPublicKeyLoadedException();
            }
        }

        return [
            'public' => $publicKey,
            'public-hashed' => $publicKeyHash,
            'private' => $privateKey,
            'private-hashed' => $privateKeyHash,
            'loaded-version' => $loadedVersion,
            'loaded-size' => $loadedSize,
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded public key (static function).
     *
     * @param string $publicKey
     * @return array{'private': null, 'private-hashed': ?string, 'public': string, 'public-hashed': string, 'loaded-version': ?string, 'loaded-size': int}
     * @throws Exception
     */
    public static function getPairFromPublicKey(string $publicKey): array
    {
        $privateKeyLoaded = true;

        /* Try to load private key. */
        try {
            $return = self::getPairFromPrivateKey($publicKey);

            if ($return['loaded-version'] === self::VERSION_1) {
                $privateKeyLoaded = false;
            }
        } catch (PHPVaultPublicKeyLoadedException $e) {
            $privateKeyLoaded = false;
        }

        /* A private key was loaded. */
        if ($privateKeyLoaded) {
            throw new PHPVaultPrivateKeyLoadedException();
        }

        $publicKeyArray = array();
        $loadedVersion = self::VERSION_1;
        $loadedSize = strlen($publicKey);

        if (self::isJson(base64_decode($publicKey))) {
            $publicKeyArray = json_decode(base64_decode($publicKey));
            $publicKey = $publicKeyArray[0];
        }

        $privateKey = null;
        $privateKeyHash = null;
        $publicKeyHash = md5($publicKey);

        /* Private key hash given. */
        if (count($publicKeyArray) > 1) {
            $privateKeyHash = $publicKeyArray[1];
            $loadedVersion = self::VERSION_2;
        }

        return [
            'public' => $publicKey,
            'public-hashed' => $publicKeyHash,
            'private' => $privateKey,
            'private-hashed' => $privateKeyHash,
            'loaded-version' => $loadedVersion,
            'loaded-size' => $loadedSize,
        ];
    }

    /**
     * Check if given string is json encoded.
     *
     * @param string $string
     * @return bool
     */
    public static function isJson(string $string): bool
    {
        json_decode($string);

        return json_last_error() === JSON_ERROR_NONE;
    }
}
