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

class Writer
{
    const TEMPLATE_ENV_VALUE = '%s="%s"';

    const TEMPLATE_ENV_DESCRIPTION = '# %s';

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
     * @return array
     * @throws Exception
     */
    public function saveToEnv(): array
    {
        foreach ($this->vault->getAllDecrypted(true) as $key => $value) {
            $_ENV[$key] = $value;
        }

        return $_ENV;
    }

    /**
     * Returns the .env string of decrypted vault values.
     *
     * @param bool $decrypted
     * @param bool $withDescription
     * @return string
     * @throws Exception
     */
    public function getEnvString(bool $decrypted = false, bool $withDescription = false): string
    {
        $data = $this->vault->getAll(true, true, $decrypted);

        $envString = '';

        foreach ($data as $key => $vaultItem) {
            if (!empty($envString)) {
                $envString .= $withDescription ? "\n\n" : "\n";
            }

            if ($withDescription) {
                $envString .= sprintf(self::TEMPLATE_ENV_DESCRIPTION, $vaultItem->description)."\n";
            }

            $envString .= sprintf(self::TEMPLATE_ENV_VALUE, $key, $vaultItem->value);
        }

        return $envString;
    }
}