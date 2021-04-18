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
     * @param bool $decrypt
     * @return object[]
     * @throws Exception
     */
    public function convertStreamToArray(string $stream, bool $decrypt = false): array
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
                $current->description = $this->vault->convertString($matches[1], $decrypt);

                /* go to next line */
                continue;
            }

            /* NAME=VALUE detected */
            if (preg_match(self::PATTERN_NAME_VALUE, $line, $matches)) {

                /* add parsed values to current array */
                $current->name = $matches[1];
                $current->value = $matches[2];

                /* add current array to return array */
                $return[$this->vault->getUnderscoredKey($current->name)] = (object) [
                    'value' => $this->vault->convertString($current->value, $decrypt),
                    'description' => $current->description,
                ];

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
        $this->addArrayToVault($this->convertStreamToArray($stream), null, $encryptedStream);
    }

    /**
     * Adds given array to vault.
     *
     * @param object[] $array
     * @param string|null $nonce
     * @param bool $encryptedArray
     * @return void
     * @throws SodiumException
     */
    public function addArrayToVault(array $array, string $nonce = null, bool $encryptedArray = false): void
    {
        foreach ($array as $name => $data) {
            $this->vault->add($name, $data->value, $data->description, $nonce, $encryptedArray);
        }
    }
}
