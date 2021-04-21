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

use SodiumException;
use Exception;

class Reader
{
    protected Vault $vault;

    const PATTERN_NAME_VALUE = '~^([a-z][a-z0-9_]+)=(.+)$~i';

    const PATTERN_DESCRIPTION = '~^#[ ]?(.+)$~i';

    const LOAD_FROM_ENCRYPTED = false;

    const LOAD_FROM_DECRYPTED = true;

    const OUTPUT_TO_ENCRYPTED = false;

    const OUTPUT_TO_DECRYPTED = true;

    /**
     * Writer constructor.
     *
     * @param Vault $vault
     */
    public function __construct(Vault $vault)
    {
        $this->vault = $vault;
    }

    /**
     * Converts given stream to array.
     *
     * @param string $stream
     * @param bool $loadAsDecrypted
     * @param bool $outputAsDecrypted
     * @param string|null $nonce
     * @return KeyValuePair[]
     * @throws SodiumException
     */
    public function convertStreamToArray(string $stream, bool $loadAsDecrypted = false, bool $outputAsDecrypted = false, string $nonce = null): array
    {
        $lines = explode("\n", $stream);
        $return = array();

        $default = (object) [
            'name' => null,
            'value' => null,
            'description' => null,
        ];

        $current = clone $default;
        foreach ($lines as $line) {
            $matches = array();

            /* # DESCRIPTION detected */
            if (preg_match(self::PATTERN_DESCRIPTION, $line, $matches)) {

                /* add parsed values to current array */
                $current->description = $matches[1];

                /* go to next line */
                continue;
            }

            /* NAME=VALUE detected */
            if (preg_match(self::PATTERN_NAME_VALUE, $line, $matches)) {

                /* add parsed values to current array */
                $current->name = $matches[1];
                $current->value = $matches[2];

                /* add current array to return array */
                if ($loadAsDecrypted) {
                    /* decrypted */
                    if ($outputAsDecrypted) {
                        $return[$this->vault->getUnderscoredKey($current->name)] = new KeyValuePair(
                            $this->vault->getUnderscoredKey($current->name),
                            null,
                            null,
                            $this->vault->convertString($current->value, false, false),
                            $this->vault->convertString($current->description, false, false)
                        );
                    /* encrypted */
                    } else {
                        $return[$this->vault->getUnderscoredKey($current->name)] = new KeyValuePair(
                            $this->vault->getUnderscoredKey($current->name),
                            $this->vault->convertString($current->value, false, true, $nonce),
                            $this->vault->convertString($current->description, false, true, $nonce)
                        );
                    }
                } else {
                    if ($outputAsDecrypted) {
                        $return[$this->vault->getUnderscoredKey($current->name)] = new KeyValuePair(
                            $this->vault->getUnderscoredKey($current->name),
                            null,
                            null,
                            $this->vault->convertString($current->value, true, false),
                            $this->vault->convertString($current->description, true, false)
                        );
                    } else {
                        $return[$this->vault->getUnderscoredKey($current->name)] = new KeyValuePair(
                            $this->vault->getUnderscoredKey($current->name),
                            $this->vault->convertString($current->value, false, false),
                            $this->vault->convertString($current->description, false, false)
                        );
                    }
                }

                /* create new current array */
                $current = clone $default;

                /* go to next line */
                continue;
            }
        }

        return $return;
    }

    /**
     * Adds given file to vault.
     *
     * @param string $file
     * @param bool $encryptedFile
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function addFileToVault(string $file, bool $encryptedFile = false): void
    {
        /* Check given file. */
        if (!file_exists($file)) {
            throw new Exception(sprintf('The given file "%s" does not exist.', $file));
        }

        /* Load file. */
        $fileContent = file_get_contents($file);

        /* Check loaded file. */
        if ($fileContent === false) {
            throw new Exception(sprintf('The given file "%s" could not be loaded.', $file));
        }

        $this->addStreamToVault($fileContent, $encryptedFile);
    }

    /**
     * Adds given stream to vault.
     *
     * @param string $stream
     * @param bool $encryptedStream
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function addStreamToVault(string $stream, bool $encryptedStream = false): void
    {
        if ($encryptedStream) {
            $array = $this->convertStreamToArray($stream, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_ENCRYPTED);
        } else {
            $array = $this->convertStreamToArray($stream, Reader::LOAD_FROM_DECRYPTED, Reader::OUTPUT_TO_ENCRYPTED);
        }

        $this->addArrayToVault($array, null, true);
    }

    /**
     * Adds given array to vault.
     *
     * @param KeyValuePair[] $array
     * @param string|null $nonce
     * @param bool $encryptedArray
     * @return void
     * @throws SodiumException
     */
    public function addArrayToVault(array $array, string $nonce = null, bool $encryptedArray = false): void
    {
        foreach ($array as $name => $data) {
            if ($encryptedArray) {
                $this->vault->add($name, $data->getValueEncrypted(), $data->getDescriptionEncrypted(), $nonce, $encryptedArray);
            } else {
                $this->vault->add($name, $data->getValueDecrypted(), $data->getDescriptionDecrypted(), $nonce, $encryptedArray); // TODO: What about $encryptedArray? This should be !$encryptedArray? Test breaks.
            }
        }
    }
}
