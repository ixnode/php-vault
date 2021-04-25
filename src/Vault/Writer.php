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

class Writer
{
    const TEMPLATE_ENV_VALUE = '%s="%s"';

    const TEMPLATE_ENV_DESCRIPTION = '# %s';

    const ENV_PREFIX = 'PHPVAULT_';

    protected Vault $vault;

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
     * Saves all decrypted vault values to $_ENV array.
     *
     * @return string[]
     * @throws Exception
     */
    public function saveToEnv(): array
    {
        foreach ($this->vault->getAllValuesFromVaultDecrypted(true) as $key => $value) {
            $_ENV[$this->getPhpVaultEnvironmentKey($key)] = $value;
        }

        return $_ENV;
    }

    /**
     * Saves all decrypted vault values to $_SERVER array.
     *
     * @return string[]
     * @throws Exception
     */
    public function saveToServer(): array
    {
        foreach ($this->vault->getAllValuesFromVaultDecrypted(true) as $key => $value) {
            $_SERVER[$this->getPhpVaultEnvironmentKey($key)] = $value;
        }

        return $_SERVER;
    }

    /**
     * Saves all decrypted vault values to putenv.
     *
     * @return void
     * @throws Exception
     */
    public function putEnv(): void
    {
        foreach ($this->vault->getAllValuesFromVaultDecrypted(true) as $key => $value) {
            putenv(sprintf('%s=%s', $this->getPhpVaultEnvironmentKey($key), $value));
        }
    }

    /**
     * Returns the PHPVault key name used by system environment.
     *
     * @param string $key
     * @return string
     */
    public function getPhpVaultEnvironmentKey(string $key): string
    {
        if (preg_match(sprintf('~^%s~', self::ENV_PREFIX), $key)) {
            return $key;
        }

        return sprintf('%s%s', self::ENV_PREFIX, $key);
    }

    /**
     * Filters the given array by own used and created PHPVAULT_ elements. Do not return system variables.
     *
     * @param string[] $array
     * @return string[]
     */
    public function filterArrayByNonePhpVaultEnvironmentKeys(array $array): array
    {
        return array_filter(
            $array,
            function (string $key) {
                return (bool)preg_match(sprintf('~^%s~', self::ENV_PREFIX), $key);
            },
            ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * Returns the .env string of decrypted vault values.
     *
     * @param string $outputType
     * @param bool $withDescription
     * @return string
     * @throws SodiumException
     * @throws Exception
     */
    public function getEnvString(string $outputType = Reader::OUTPUT_TO_ENCRYPTED, bool $withDescription = false): string
    {
        $data = $this->vault->getAllKeyValuePairs(true, $outputType);

        $envString = '';
        $getDecrypted = $outputType === Reader::OUTPUT_TO_DECRYPTED;

        foreach ($data as $key => $vaultItem) {
            if (!empty($envString)) {
                $envString .= $withDescription ? "\n\n" : "\n";
            }

            if ($withDescription && $vaultItem->getDescription($getDecrypted) !== null) {
                $envString .= sprintf(self::TEMPLATE_ENV_DESCRIPTION, $vaultItem->getDescription($getDecrypted))."\n";
            }

            $envString .= sprintf(self::TEMPLATE_ENV_VALUE, $key, $vaultItem->getValue($getDecrypted));
        }

        return $envString;
    }
}
