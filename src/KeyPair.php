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
    private PHPVault $core;

    private ?string $privateKey = null;

    private ?string $publicKey = null;

    const SERVER_PUBLIC_KEY_NAME = 'PUBLIC_KEY';

    const SERVER_PRIVATE_KEY_NAME = 'PRIVATE_KEY';

    /**
     * KeyPair constructor.
     *
     * @param PHPVault $core
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @throws SodiumException
     */
    public function __construct(PHPVault $core, bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null)
    {
        $this->core = $core;

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
        $this->core->setMode(Mode::MODE_NONE);
    }

    /**
     * Sets private key pair from given array.
     *
     * @param array{'private': string|null, 'public': string} $keyPair
     * @return void
     */
    protected function setKeyPair(array $keyPair): void
    {
        $this->setPrivateKey($keyPair['private']);
        $this->setPublicKey($keyPair['public']);
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
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function renew(bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null, bool $throwException = true): void
    {
        /* Delete key pair. */
        $this->deleteKeyPair();

        /* Force create new key pair */
        if ($this->core->getMode() === Mode::MODE_NONE && $forceCreateNew) {
            $this->setKeyPair(self::getNewPair());
            $this->core->setMode(Mode::MODE_DECRYPT);
        }


        /* Read private key from input parameter */
        if ($this->core->getMode() === Mode::MODE_NONE && $privateKey !== null) {
            $this->setKeyPair(self::getPairFromPrivateKey($privateKey));
            $this->core->setMode(Mode::MODE_DECRYPT);
        }

        /* Read private key from $_SERVER variable. */
        if ($this->core->getMode() === Mode::MODE_NONE && array_key_exists(self::SERVER_PRIVATE_KEY_NAME, $_SERVER)) {
            $this->setKeyPair(self::getPairFromPrivateKey($_SERVER[self::SERVER_PRIVATE_KEY_NAME]));
            $this->core->setMode(Mode::MODE_DECRYPT);
        }


        /* Read public key from input parameter */
        if ($this->core->getMode() === Mode::MODE_NONE && $publicKey !== null) {
            $this->setKeyPair(self::getPairFromPublicKey($publicKey));
            $this->core->setMode(Mode::MODE_ENCRYPT);
        }

        /* Read private key from $_SERVER variable. */
        if ($this->core->getMode() === Mode::MODE_NONE && array_key_exists(self::SERVER_PUBLIC_KEY_NAME, $_SERVER)) {
            $this->setKeyPair(self::getPairFromPublicKey($_SERVER[self::SERVER_PUBLIC_KEY_NAME]));
            $this->core->setMode(Mode::MODE_ENCRYPT);
        }


        /* No key was found. */
        if ($this->core->getMode() === Mode::MODE_NONE && $throwException) {
            throw new Exception('No private or public key found.');
        }
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

        $this->renew(false, $privateKeyString);
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

        $this->renew(false, null, $publicKey);
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
