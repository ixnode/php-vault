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

namespace Ixnode\PhpVault\Tools;

use Exception;
use Ixnode\PhpVault\PHPVault;

class Converter {

    /**
     * Transform a given key to an UNDER_SCORE key.
     *
     * @param string $keyName
     * @return string
     */
    public static function getUnderscoredKey(string $keyName): string
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
     * @param PHPVault $phpVaultCore
     * @param string|null $string $string
     * @param bool $decrypt
     * @param bool $encrypt
     * @param string|null $nonce
     * @return string|null
     * @throws Exception
     */
    public static function convertString(PHPVault $phpVaultCore, ?string $string, bool $decrypt = false, bool $encrypt = false, string $nonce = null): ?string
    {
        if ($string === null) {
            return null;
        }

        $string = preg_replace('~^[\'"]?(.*?)[\'"]?$~', '$1', $string);

        if ($decrypt) {
            $string = $phpVaultCore->getDecrypter()->decrypt($string);
        }

        if ($encrypt) {
            $string = $phpVaultCore->getEncrypter()->encrypt($string, $nonce);
        }

        return $string;
    }
}

