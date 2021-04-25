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
use Ixnode\PhpVault\Tools\Converter;

class Vault
{
    /** @var PHPVault $phpVaultCore */
    private PHPVault $phpVaultCore;

    /** @var Reader $reader */
    private Reader $reader;

    /** @var Writer $writer */
    private Writer $writer;

    /** @var KeyValuePair[] $vault  */
    private array $vault = [];

    /**
     * Vault constructor.
     *
     * @param PHPVault $phpVaultCore
     */
    public function __construct(PHPVault $phpVaultCore)
    {
        $this->phpVaultCore = $phpVaultCore;

        /* Set reader and writer */
        $this->reader = new Reader($this);
        $this->writer = new Writer($this);
    }

    /**
     * Returns an key value pair given by key (raw - without encrypting or decrypting).
     *
     * @param string $key
     * @return KeyValuePair
     * @throws Exception
     */
    public function getKeyValuePairRaw(string $key): object
    {
        if (!array_key_exists($key, $this->vault)) {
            throw new Exception('Unknown given key name.');
        }

        return $this->vault[$key];
    }

    /**
     * Returns an already decrypted or encrypted key value pair given by key.
     *
     * @param string $key
     * @param bool $decrypt
     * @return KeyValuePair
     * @throws Exception
     */
    public function getKeyValuePair(string $key, bool $decrypt = false): object
    {
        if ($decrypt) {
            return $this->getKeyValuePairRaw($key)->decrypt($this->phpVaultCore->getDecrypter());
        } else {
            return $this->getKeyValuePairRaw($key)->encrypt($this->phpVaultCore->getEncrypter());
        }
    }

    /**
     * Returns an already encrypted key value pair given by key.
     *
     * @param string $key
     * @return KeyValuePair
     * @throws SodiumException
     * @throws Exception
     */
    public function getKeyValuePairEncrypted(string $key): object
    {
        return $this->getKeyValuePair($key);
    }

    /**
     * Returns an already decrypted key value pair given by key.
     *
     * @param string $key
     * @return KeyValuePair
     * @throws SodiumException
     * @throws Exception
     */
    public function getKeyValuePairDecrypted(string $key): object
    {
        return $this->getKeyValuePair($key, true);
    }

    /**
     * Returns all values of the vault encrypted or decrypted.
     *
     * @param bool $underscored
     * @param bool $decrypt
     * @return string[]|null[]
     * @throws Exception
     */
    public function getAllValuesFromVault(bool $underscored = false, bool $decrypt = false): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? Converter::getUnderscoredKey($key) : $key;

            $vault[$keyArray] = $decrypt ? $this->getKeyValuePairRaw($key)->getValueDecrypted() : $this->getKeyValuePairRaw($key)->getValueEncrypted();
        }

        return $vault;
    }

    /**
     * Returns all values of the vault encrypted.
     *
     * @param bool $underscored
     * @return string[]|null[]
     * @throws Exception
     */
    public function getAllValuesFromVaultEncrypted(bool $underscored = false): array
    {
        return $this->getAllValuesFromVault($underscored);
    }

    /**
     * Returns all values of the vault decrypted.
     *
     * @param bool $underscored
     * @return string[]|null[]
     * @throws Exception
     */
    public function getAllValuesFromVaultDecrypted(bool $underscored = false): array
    {
        return $this->getAllValuesFromVault($underscored, true);
    }

    /**
     * Returns the whole raw vault as KeyValuePair array (raw - without encrypting or decrypting).
     *
     * @param bool $underscored
     * @return KeyValuePair[]
     * @throws Exception
     */
    public function getAllKeyValuePairsRaw(bool $underscored = false): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? Converter::getUnderscoredKey($key) : $key;

            $vault[$keyArray] = $this->getKeyValuePairRaw($key);
        }

        return $vault;
    }

    /**
     * Returns the whole decrypted or encrypted vault as object array.
     *
     * @param bool $underscored
     * @param string $outputType
     * @return KeyValuePair[]
     * @throws SodiumException
     * @throws Exception
     */
    public function getAllKeyValuePairs(bool $underscored = false, string $outputType = Reader::OUTPUT_TO_ENCRYPTED): array
    {
        $vault = [];

        foreach (array_keys($this->vault) as $key) {
            $keyArray = $underscored ? Converter::getUnderscoredKey($key) : $key;

            switch ($outputType) {
                case Reader::OUTPUT_TO_DECRYPTED:
                    $vault[$keyArray] = $this->getKeyValuePairDecrypted($key);
                    break;

                case Reader::OUTPUT_TO_ENCRYPTED:
                    $vault[$keyArray] = $this->getKeyValuePairEncrypted($key);
                    break;

                default:
                    throw new Exception('Unknown given output type.');
            }
        }

        return $vault;
    }

    /**
     * Returns the whole encrypted vault as object array.
     *
     * @param bool $underscored
     * @return KeyValuePair[]
     * @throws SodiumException
     */
    public function getAllKeyValuePairsEncrypted(bool $underscored = false): array
    {
        return $this->getAllKeyValuePairs($underscored);
    }

    /**
     * Returns the whole decrypted vault as object array.
     *
     * @param bool $underscored
     * @return KeyValuePair[]
     * @throws SodiumException
     */
    public function getAllKeyValuePairsDecrypted(bool $underscored = false): array
    {
        return $this->getAllKeyValuePairs($underscored, Reader::OUTPUT_TO_DECRYPTED);
    }

    /**
     * Adds given KeyPair to vault.
     *
     * @param string $key
     * @param KeyValuePair $keyPair
     * @return KeyValuePair[]
     */
    public function addKeyValuePair(string $key, KeyValuePair $keyPair): array
    {
        $this->vault[$key] = $keyPair;

        return $this->vault;
    }

    /**
     * Adds given name and value to vault.
     *
     * @param string $key
     * @param ?string $value
     * @param ?string $description
     * @param ?string $nonce
     * @param bool $alreadyEncrypted
     * @return KeyValuePair[]
     * @throws SodiumException
     * @throws Exception
     */
    public function add(string $key, string $value = null, string $description = null, string $nonce = null, bool $alreadyEncrypted = false): array
    {
        if ($alreadyEncrypted) {
            $decryptedValue = null;
            $decryptedDescription = null;
            $encryptedValue = $value;
            $encryptedDescription = $description;
        } else {
            $decryptedValue = $value;
            $decryptedDescription = $description;
            $encryptedValue = $value === null ? null : $this->phpVaultCore->getEncrypter()->encrypt($value, $nonce);
            $encryptedDescription = $description === null ? null : $this->phpVaultCore->getEncrypter()->encrypt($description, $nonce);
        }

        return $this->addKeyValuePair($key, new KeyValuePair($key, $encryptedValue, $encryptedDescription, $decryptedValue, $decryptedDescription));
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

    /**
     * Returns the PHPVault core.
     *
     * @return PHPVault
     */
    public function getPhpVaultCore(): PHPVault
    {
        return $this->phpVaultCore;
    }
}
