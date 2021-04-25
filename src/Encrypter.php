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

class Encrypter
{
    const PATTERN_ALREADY_DECRYPTED = '~^Wy[IJ][A-Za-z0-9]+[=]*$~';

    protected PHPVault $phpVaultCore;

    /**
     * Decrypter constructor.
     *
     * @param PHPVault $phpVaultCore
     */
    public function __construct(PHPVault $phpVaultCore)
    {
        $this->phpVaultCore = $phpVaultCore;
    }

    /**
     * Encrypts a given message.
     *
     * @param string $message
     * @param string|null $nonce
     * @return string|null
     * @throws SodiumException
     * @throws Exception
     */
    public function encrypt(string $message, string $nonce = null): ?string
    {
        /* Check encryption mode (private or public key). */
        if ($this->phpVaultCore->getMode() < Mode::MODE_ENCRYPT) {
            throw new Exception(KeyPair::TEXT_NO_PUBLIC_KEY_LOADED);
        }

        /* Try to load public key. */
        $publicKey = $this->phpVaultCore->getKeyPair()->getPublicKey();
        if ($publicKey === null) {
            throw new Exception(KeyPair::TEXT_NO_PUBLIC_KEY_LOADED);
        }

        /* Check whether the message is already encrypted. */
        if (preg_match(self::PATTERN_ALREADY_DECRYPTED, $message)) {
            throw new Exception(sprintf('Encrypter::encrypt: The given message "%s" seems to be encrypted.', $message));
        }

        /* Use given or new random nonce. */
        $nonce = base64_decode($nonce === null ? Nonce::getNewNonce() : $nonce);

        /* Get crypto box keypair. */
        $key = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            base64_decode(PHPVault::CORE_PRIVATE_KEY),
            base64_decode($publicKey)
        );

        /* Build data array. */
        $dataArray = array(
            base64_encode($nonce),
            base64_encode(sodium_crypto_box($message, $nonce, $key))
        );

        $json = json_encode($dataArray);

        if ($json === false) {
            return null;
        }

        return base64_encode($json);
    }
}
