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

use Ixnode\PhpVault\Exception\PHPVaultCorruptedDataException;
use Ixnode\PhpVault\Exception\PHPVaultNoPrivateKeyLoadedException;
use Ixnode\PhpVault\Exception\PHPVaultVerificationFailedException;
use SodiumException;
use Exception;

class Decrypter
{
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
     * Decrypts a given message stream with given private key.
     *
     * @param string $data
     * @return string|null
     * @throws SodiumException
     * @throws PHPVaultVerificationFailedException
     * @throws PHPVaultNoPrivateKeyLoadedException
     * @throws PHPVaultCorruptedDataException
     * @throws Exception
     */
    public function decrypt(string $data): ?string
    {
        /* Check encryption mode (private key given). */
        if ($this->phpVaultCore->getMode() < Mode::MODE_DECRYPT) {
            throw new PHPVaultNoPrivateKeyLoadedException();
        }

        /* Try to load private key. */
        $privateKey = $this->phpVaultCore->getKeyPair()->getPrivateKey();
        if ($privateKey === null) {
            throw new PHPVaultNoPrivateKeyLoadedException();
        }

        /* Get crypto box keypair. */
        $key = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            base64_decode($privateKey),
            base64_decode(PHPVault::CORE_PUBLIC_KEY)
        );

        /* Extract data array. */
        $dataArray = json_decode(base64_decode($data), true);

        /* Check whether the value could be decrypted. */
        if (gettype($dataArray) !== 'array') {
            throw new PHPVaultCorruptedDataException();
        }

        $nonce = base64_decode($dataArray[0]);
        $encryptedMessage = base64_decode($dataArray[1]);

        /* Decrypt message */
        $decrypted = sodium_crypto_box_open($encryptedMessage, $nonce, $key);

        /* Verification of given private key and message failed. */
        if ($decrypted === false) {
            throw new PHPVaultVerificationFailedException();
        }

        return $decrypted;
    }
}
