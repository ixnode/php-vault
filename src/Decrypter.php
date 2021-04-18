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

use SodiumException;
use Exception;

class Decrypter
{
    protected Core $core;

    /**
     * Decrypter constructor.
     *
     * @param Core $core
     */
    public function __construct(Core $core)
    {
        $this->core = $core;
    }

    /**
     * Decrypts a given message stream with given private key.
     *
     * @param string $data
     * @return false|string
     * @throws SodiumException
     * @throws Exception
     */
    public function decrypt(string $data)
    {
        /* Check mode */
        if ($this->core->getMode() < Mode::MODE_DECRYPT) {
            throw new Exception('Decrypter::decrypt: The Decrypter class is not able to decrypt strings. Please load a private key to do this.');
        }

        $key = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            base64_decode($this->core->getKeyPair()->getPrivate()),
            base64_decode(Core::CORE_PUBLIC_KEY)
        );

        $dataArray = json_decode(base64_decode($data), true);

        /* Check whether the value could be decrypted. */
        if (gettype($dataArray) !== 'array') {
            throw new Exception('Decrypter::decrypt: Unable to decrypt the given data block.');
        }

        $nonce = base64_decode($dataArray[0]);
        $encryptedMessage = base64_decode($dataArray[1]);

        return sodium_crypto_box_open($encryptedMessage, $nonce, $key);
    }
}
