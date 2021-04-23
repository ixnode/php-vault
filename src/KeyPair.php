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
use SodiumException;

class KeyPair
{
    private PHPVault $phpVaultCore;

    private ?string $privateKey = null;

    private ?string $publicKey = null;

    protected ?string $loadedFromSource = null;

    protected ?string $loadedFromPath = null;

    protected ?string $loadedFromEnvironment = null;

    const SERVER_PUBLIC_KEY_NAME = 'PUBLIC_KEY';

    const SERVER_PRIVATE_KEY_NAME = 'PRIVATE_KEY';

    const LOADED_FROM_FILE = 'FILE';

    const LOADED_FROM_ENVIRONMENT = 'ENVIRONMENT';

    const LOADED_FROM_PASSED_STRING = 'PASSED_STRING';

    const LOADED_FROM_RANDOM_GENERATOR = 'RANDOM_GENERATOR';

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
    }

    /**
     * Sets private key pair from given array.
     *
     * @param array{'private': string|null, 'public': string} $keyPair
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
     * @return array{'private': string, 'public': string}
     * @throws SodiumException
     */
    static public function getNewPair(): array
    {
        $keyPair = sodium_crypto_box_keypair();

        return [
            'public' => base64_encode(sodium_crypto_box_publickey($keyPair)),
            'private' => base64_encode(sodium_crypto_box_secretkey($keyPair))
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded private key (static function).
     *
     * @param string $privateKey
     * @return array{'private': string, 'public': string}
     * @throws SodiumException
     */
    static public function getPairFromPrivateKey(string $privateKey): array
    {
        return [
            'public' => base64_encode(sodium_crypto_box_publickey_from_secretkey(base64_decode($privateKey))),
            'private' => $privateKey
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded public key (static function).
     *
     * @param string $publicKey
     * @return array{'private': null, 'public': string}
     */
    static public function getPairFromPublicKey(string $publicKey): array
    {
        return [
            'public' => $publicKey,
            'private' => null
        ];
    }
}
