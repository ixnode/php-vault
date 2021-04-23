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

use Ixnode\PhpVault\Tools\Converter;
use SodiumException;
use Exception;

class Reader
{
    protected Vault $vault;

    const PATTERN_NAME_VALUE = '~^([a-z][a-z0-9_]+)=(.+)$~i';

    const PATTERN_DESCRIPTION = '~^#[ ]?(.+)$~i';

    const LOAD_FROM_ENCRYPTED = 'LOAD_ENCRYPTED';

    const LOAD_FROM_DECRYPTED = 'LOAD_DECRYPTED';

    const OUTPUT_TO_ENCRYPTED = 'SHOW_ENCRYPTED';

    const OUTPUT_TO_DECRYPTED = 'SHOW_DECRYPTED';

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
     * @param string $loadType
     * @param string $outputType
     * @param string|null $nonce
     * @return KeyValuePair[]
     * @throws SodiumException
     * @throws Exception
     */
    public function convertStreamToKeyPairArray(string $stream, string $loadType = self::LOAD_FROM_ENCRYPTED, string $outputType = self::OUTPUT_TO_ENCRYPTED, string $nonce = null): array
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

                $underscoredKey = Converter::getUnderscoredKey($current->name);

                /* add current array to return array */
                if ($loadType === self::LOAD_FROM_DECRYPTED) {
                    /* decrypted */
                    if ($outputType === self::OUTPUT_TO_DECRYPTED) {
                        $return[$underscoredKey] = new KeyValuePair(
                            $underscoredKey,
                            null,
                            null,
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->value, false, false),
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->description, false, false)
                        );
                    /* encrypted */
                    } else {
                        $return[$underscoredKey] = new KeyValuePair(
                            $underscoredKey,
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->value, false, true, $nonce),
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->description, false, true, $nonce)
                        );
                    }
                } else {
                    if ($outputType === self::OUTPUT_TO_DECRYPTED) {
                        $return[$underscoredKey] = new KeyValuePair(
                            $underscoredKey,
                            null,
                            null,
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->value, true, false),
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->description, true, false)
                        );
                    } else {
                        $return[$underscoredKey] = new KeyValuePair(
                            $underscoredKey,
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->value, false, false),
                            Converter::convertString($this->vault->getPhpVaultCore(), $current->description, false, false)
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
     * Adds given array to vault (old).
     *
     * @param KeyValuePair[] $array
     * @param string|null $nonce
     * @return void
     * @throws SodiumException
     */
    public function addArrayToVault(array $array, string $nonce = null): void
    {
        foreach ($array as $name => $data) {
            if ($data->getValueDecrypted() !== null) {
                $this->vault->add($name, $data->getValueDecrypted(), $data->getDescriptionDecrypted(), $nonce);
            } else {
                $this->vault->add($name, $data->getValueEncrypted(), $data->getDescriptionEncrypted(), $nonce, true);
            }
        }
    }

    /**
     * Adds given key pair array to vault.
     *
     * @param KeyValuePair[] $array
     * @return void
     */
    public function addKeyValuePairArrayToVault(array $array): void
    {
        foreach ($array as $name => $keyPair) {
            $this->vault->addKeyValuePair($name, $keyPair);
        }
    }

    /**
     * Adds given stream to vault.
     *
     * @param string $stream
     * @param string $loadType
     * @param string $outputType
     * @return void
     * @throws SodiumException
     */
    public function addStreamToVault(string $stream, string $loadType = self::LOAD_FROM_ENCRYPTED, string $outputType = self::OUTPUT_TO_ENCRYPTED): void
    {
        $this->addKeyValuePairArrayToVault($this->convertStreamToKeyPairArray($stream, $loadType, $outputType));
    }

    /**
     * Adds given file to vault.
     *
     * @param string $file
     * @param string $loadType
     * @param string $outputType
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function addFileToVault(string $file, string $loadType = self::LOAD_FROM_ENCRYPTED, string $outputType = self::OUTPUT_TO_ENCRYPTED): void
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

        $this->addStreamToVault($fileContent, $loadType, $outputType);
    }
}
