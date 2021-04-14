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
    private Core $core;

    private ?object $keyPair = null;

    const SERVER_PUBLIC_KEY_NAME = 'PUBLIC_KEY';

    const SERVER_PRIVATE_KEY_NAME = 'PRIVATE_KEY';

    /**
     * KeyPair constructor.
     *
     * @param Core $core
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @throws SodiumException
     */
    public function __construct(Core $core, bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null)
    {
        $this->core = $core;

        /* Renew key if given. */
        if ($forceCreateNew || $privateKey !== null || $publicKey !== null) {
            $this->renew($forceCreateNew, $privateKey, $publicKey);
        }
    }

    /**
     * Returns the base64 encoded private string.
     *
     * @return string
     */
    public function getPrivate(): string
    {
        return $this->keyPair->private;
    }

    /**
     * Returns the base64 decoded public string.
     *
     * @return string
     */
    public function getPublic(): string
    {
        return $this->keyPair->public;
    }

    /**
     * Renews the saved public private key.
     *
     * @param bool $forceCreateNew
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @throws SodiumException
     * @throws Exception
     */
    public function renew(bool $forceCreateNew = false, string $privateKey = null, string $publicKey = null): void
    {
        /* Force create new key pair */
        if ($this->keyPair === null && $forceCreateNew) {
            $this->keyPair = self::getNewPair();
            $this->core->setMode(Mode::MODE_DECRYPT);
        }


        /* Read private key from input parameter */
        if ($this->keyPair === null && $privateKey !== null) {
            $this->keyPair = self::getPairFromPrivateKey($privateKey);
            $this->core->setMode(Mode::MODE_DECRYPT);
        }

        /* Read private key from $_SERVER variable. */
        if ($this->keyPair === null && array_key_exists(self::SERVER_PRIVATE_KEY_NAME, $_SERVER)) {
            $this->keyPair = self::getPairFromPrivateKey($_SERVER[self::SERVER_PRIVATE_KEY_NAME]);
            $this->core->setMode(Mode::MODE_DECRYPT);
        }


        /* Read public key from input parameter */
        if ($this->keyPair === null && $publicKey !== null) {
            $this->keyPair = self::getPairFromPublicKey($publicKey);
            $this->core->setMode(Mode::MODE_ENCRYPT);
        }

        /* Read private key from $_SERVER variable. */
        if ($this->keyPair === null && array_key_exists(self::SERVER_PUBLIC_KEY_NAME, $_SERVER)) {
            $this->keyPair = self::getPairFromPublicKey($_SERVER[self::SERVER_PUBLIC_KEY_NAME]);
            $this->core->setMode(Mode::MODE_ENCRYPT);
        }


        /* No key was found. */
        if ($this->keyPair === null) {
            throw new Exception('No private or public key found.');
        }
    }

    /**
     * Loads private key from file.
     *
     * @param string $privateKey
     * @throws SodiumException
     */
    public function loadPrivateKeyFromFile(string $privateKey)
    {
        /* Check that given file exists. */
        if (!file_exists($privateKey)) {
            throw new Exception(sprintf('The given private key does not exists.', $privateKey));
        }

        $this->renew(false, file_get_contents($privateKey));
    }

    /**
     * Loads public key from file.
     *
     * @param string $publicKey
     * @throws SodiumException
     */
    public function loadPublicKeyFromFile(string $publicKey)
    {
        /* Check that given file exists. */
        if (!file_exists($publicKey)) {
            throw new Exception(sprintf('The given private key does not exists.', $publicKey));
        }

        $this->renew(false, null, file_get_contents($publicKey));
    }

    /**
     * Returns a new public private key object (static function).
     *
     * @return object
     * @throws SodiumException
     */
    static public function getNewPair()
    {
        $keyPair = sodium_crypto_box_keypair();

        return (object) [
            'public' => base64_encode(sodium_crypto_box_publickey($keyPair)),
            'private' => base64_encode(sodium_crypto_box_secretkey($keyPair))
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded private key (static function).
     *
     * @param string $privateKey
     * @return object
     * @throws SodiumException
     */
    static public function getPairFromPrivateKey(string $privateKey)
    {
        return (object) [
            'public' => base64_encode(sodium_crypto_box_publickey_from_secretkey(base64_decode($privateKey))),
            'private' => $privateKey
        ];
    }

    /**
     * Returns a public private key object from given base64 encoded public key (static function).
     *
     * @param string $publicKey
     * @return object
     */
    static public function getPairFromPublicKey(string $publicKey)
    {
        return (object) [
            'public' => $publicKey,
            'private' => null
        ];
    }
}
