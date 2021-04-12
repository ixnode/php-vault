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

namespace Ixnode\PhpVault\Vault;

use Exception;
use SodiumException;
use Ixnode\PhpVault\Core;

class Vault
{
    private Core $core;

    private Writer $writer;

    private array $vault = [];

    /**
     * Vault constructor.
     *
     * @param Core $core
     */
    public function __construct(Core $core)
    {
        $this->core = $core;

        $this->writer = new Writer($this);
    }

    /**
     * Gets the whole vault.
     *
     * @param bool $underscored
     * @param bool $allProperties
     * @param bool $decrypt
     * @return array
     * @throws Exception
     */
    public function getAll(bool $underscored = false, bool $allProperties = false, bool $decrypt = false): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? $this->getUnderscoredKey($key) : $key;

            $vault[$keyArray] = $decrypt ?
                $this->decrypt($key, $allProperties) :
                $this->get($key, $allProperties);
        }

        return $vault;
    }

    /**
     * Gets the whole decrypted vault.
     *
     * @param bool $underscored
     * @param bool $allProperties
     * @return array
     * @throws Exception
     */
    public function getAllDecrypted(bool $underscored = false, bool $allProperties = false): array
    {
        return $this->getAll($underscored, $allProperties, true);
    }

    /**
     * Gets a single vault entry.
     *
     * @param string $key
     * @param bool $allProperties
     * @return object|string
     * @throws Exception
     */
    public function get(string $key, bool $allProperties = false): string|object
    {
        if (!array_key_exists($key, $this->vault)) {
            throw new Exception('Unknown given key name.');
        }

        return $allProperties ? $this->vault[$key] : $this->vault[$key]->value;
    }

    /**
     * Gets a single vault entry encrypted.
     *
     * @param string $key
     * @param bool $allProperties
     * @return object|string
     * @throws SodiumException
     * @throws Exception
     */
    public function decrypt(string $key, bool $allProperties = false): string|object
    {
        $data = $this->get($key, $allProperties);

        switch (gettype($data)) {
            case 'string':
                return $this->core->getDecrypter()->decrypt($data);

            case 'object':
                $return = (object) [];
                foreach ($data as $key => $encryptedValue) {
                    $return->{$key} = $this->core->getDecrypter()->decrypt($data->{$key});
                }
                return $return;

            default:
                throw new Exception('Unknown type given.');
        }
    }

    /**
     * Adds given name and value to vault.
     *
     * @param string $key
     * @param string $value
     * @param ?string $description
     * @param ?string $nonce
     * @throws SodiumException
     * @throws Exception
     */
    public function add(string $key, string $value, string $description = null, string $nonce = null): void
    {
        $encryptedValue = $this->core->getEncrypter()->encrypt($value, $nonce);
        $encryptedDescription = $description === null ?
            null :
            $this->core->getEncrypter()->encrypt($description, $nonce);

        $this->vault[$key] = (object) [
            'value' => $encryptedValue,
            'description' => $encryptedDescription,
        ];
    }

    /**
     * Transform a given key to an UNDER_SCORE key.
     *
     * @param string $keyName
     * @return string
     */
    public function getUnderscoredKey(string $keyName): string
    {
        /* Replace capital letters with -capital  */
        $keyName = preg_replace('~([A-Z][a-z])~', '_$1', $keyName);

        /* Replace number letters with -number  */
        $keyName = preg_replace('~([A-Za-z])([0-9])~', '$1_$2', $keyName);
        $keyName = preg_replace('~([0-9])([A-Za-z])~', '$1_$2', $keyName);

        /* Replace all - to _ */
        $keyName = str_replace('-', '_', $keyName);

        /* Replace doubled __ */
        $keyName = preg_replace('~_+~', '_', $keyName);

        /* Remove _ at the beginning */
        $keyName = preg_replace('~^_~', '', $keyName);

        /* Transform all letters to  */
        $keyName = strtoupper($keyName);

        return $keyName;
    }

    /**
     * Returns the vault writer.
     *
     * @return Writer
     */
    public function getWriter()
    {
        return $this->writer;
    }
}