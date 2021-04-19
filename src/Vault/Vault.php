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
use Ixnode\PhpVault\PHPVault;

class Vault
{
    /** @var PHPVault $core */
    private PHPVault $core;

    /** @var Reader $reader */
    private Reader $reader;

    /** @var Writer $writer */
    private Writer $writer;

    /** @var KeyValuePair[] $vault  */
    private array $vault = [];

    /**
     * Vault constructor.
     *
     * @param PHPVault $core
     */
    public function __construct(PHPVault $core)
    {
        $this->core = $core;

        /* Set reader and writer */
        $this->reader = new Reader($this);
        $this->writer = new Writer($this);
    }

    /**
     * Gets the value of a single vault entry.
     *
     * @param string $key
     * @return string
     * @throws Exception
     */
    public function getValue(string $key): string
    {
        if (!array_key_exists($key, $this->vault)) {
            throw new Exception('Unknown given key name.');
        }

        return $this->vault[$key]->getValueEncrypted();
    }

    /**
     * Gets a single vault entry as object.
     *
     * @param string $key
     * @return KeyValuePair
     * @throws Exception
     */
    public function getObject(string $key): object
    {
        if (!array_key_exists($key, $this->vault)) {
            throw new Exception('Unknown given key name.');
        }

        return $this->vault[$key];
    }

    /**
     * Gets a decrypted single value vault entry.
     *
     * @param string $key
     * @return false|string
     * @throws SodiumException
     * @throws Exception
     */
    public function getDecryptedValue(string $key)
    {
        return $this->core->getDecrypter()->decrypt($this->getValue($key));
    }

    /**
     * Gets a decrypted single full object vault entry.
     *
     * @param string $key
     * @return KeyValuePair
     * @throws SodiumException
     * @throws Exception
     */
    public function getDecryptedObject(string $key): object
    {
        return $this->getObject($key)->decrypt($this->core->getDecrypter());
    }

    /**
     * Gets the whole decrypted or encrypted vault as value array.
     *
     * @param bool $underscored
     * @param bool $decrypt
     * @return string[]
     * @throws SodiumException
     * @throws Exception
     */
    public function getAllValues(bool $underscored = false, bool $decrypt = false): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? $this->getUnderscoredKey($key) : $key;

            $value = $decrypt ? $this->getDecryptedValue($key) : $this->getValue($key);

            $vault[$keyArray] = $value === false ? null : $value;
        }

        return $vault;
    }

    /**
     * Gets the whole decrypted or encrypted vault as object array.
     *
     * @param bool $underscored
     * @param bool $decrypt
     * @return KeyValuePair[]
     * @throws SodiumException
     * @throws Exception
     */
    public function getAllObjects(bool $underscored = false, bool $decrypt = false): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? $this->getUnderscoredKey($key) : $key;

            $vault[$keyArray] = $decrypt ?
                $this->getDecryptedObject($key) :
                $this->getObject($key);
        }

        return $vault;
    }

    /**
     * Gets the whole decrypted vault as values.
     *
     * @param bool $underscored
     * @return string[]
     * @throws SodiumException
     */
    public function getAllDecryptedValues(bool $underscored = false): array
    {
        return $this->getAllValues($underscored, true);
    }

    /**
     * Gets the whole decrypted vault as objects.
     *
     * @param bool $underscored
     * @return KeyValuePair[]
     * @throws SodiumException
     */
    public function getAllDecryptedObjects(bool $underscored = false): array
    {
        return $this->getAllObjects($underscored, true);
    }

    /**
     * Adds given name and value to vault.
     *
     * @param string $key
     * @param string $value
     * @param ?string $description
     * @param ?string $nonce
     * @param bool $alreadyEncrypted
     * @return KeyValuePair[]
     * @throws SodiumException
     * @throws Exception
     */
    public function add(string $key, string $value, string $description = null, string $nonce = null, bool $alreadyEncrypted = false): array
    {
        if ($alreadyEncrypted) {
            $encryptedValue = $value;
            $encryptedDescription = $description;
        } else {
            $encryptedValue = $this->core->getEncrypter()->encrypt($value, $nonce);
            $encryptedDescription = $description === null ?
                null :
                $this->core->getEncrypter()->encrypt($description, $nonce);
        }

        $this->vault[$key] = new KeyValuePair($key, $encryptedValue, $encryptedDescription);

        return $this->vault;
    }

    /**
     * Clears the vault.
     *
     * @return void
     */
    public function clear(): void
    {
        $this->vault = [];
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

        /* Transform all letters to upper */
        return strtoupper($keyName);
    }

    /**
     * Removes quotes from string and decrypt if needed.
     *
     * @param string|null $string $string
     * @param bool $decrypt
     * @param bool $encrypt
     * @param string|null $nonce
     * @return string|null
     * @throws SodiumException
     * @throws Exception
     */
    public function convertString(?string $string, bool $decrypt = false, bool $encrypt = false, string $nonce = null): ?string
    {
        if ($string === null) {
            return null;
        }

        $string = preg_replace('~^[\'"]?(.*?)[\'"]?$~', '$1', $string);

        if ($decrypt) {
            $string = $this->core->getDecrypter()->decrypt($string);
        }

        if ($encrypt) {
            $string = $this->core->getEncrypter()->encrypt($string, $nonce);
        }

        return $string;
    }

    /**
     * Returns the vault reader.
     *
     * @return Reader
     */
    public function getReader(): Reader
    {
        return $this->reader;
    }

    /**
     * Returns the vault writer.
     *
     * @return Writer
     */
    public function getWriter(): Writer
    {
        return $this->writer;
    }
}
