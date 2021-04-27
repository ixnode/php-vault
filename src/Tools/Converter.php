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
use Ixnode\PhpVault\Exception\PHPVaultNullException;
use Ixnode\PhpVault\PHPVault;
use Ixnode\PhpVault\Vault\Reader;
use SodiumException;

class Converter {

    /**
     * Replacement for the internal php preg_replace function.
     *
     * @param string $pattern
     * @param string $replacement
     * @param string $subject
     * @param int $limit [optional]
     * @param int $count [optional]
     * @return string
     * @throws PHPVaultNullException
     */
    public static function preg_replace_string(string $pattern, string $replacement, string $subject, int $limit = -1, int &$count = 0): string
    {
        $value = preg_replace($pattern, $replacement, $subject, $limit, $count);

        if ($value === null) {
            throw new PHPVaultNullException(sprintf(PHPVaultNullException::TEXT_EXCEPTION, PHPVaultNullException::FUNCTION_PREG_REPLACE, __FILE__, __LINE__));
        }

        return $value;
    }

    /**
     * Replacement for the internal php preg_replace function.
     *
     * @param string[] $pattern
     * @param string[] $replacement
     * @param string[] $subject
     * @param int $limit [optional]
     * @param int $count [optional]
     * @return string[]
     * @throws PHPVaultNullException
     */
    public static function preg_replace_array(array $pattern, array $replacement, array $subject, int $limit = -1, int &$count = 0): array
    {
        $array = preg_replace($pattern, $replacement, $subject, $limit, $count);

        if ($array === null) {
            throw new PHPVaultNullException(sprintf(PHPVaultNullException::TEXT_EXCEPTION, PHPVaultNullException::FUNCTION_PREG_REPLACE, __FILE__, __LINE__));
        }

        return $array;
    }

    /**
     * Transform a given key to an UNDER_SCORE key.
     *
     * @param string $keyName
     * @return string
     * @throws PHPVaultNullException
     */
    public static function getUnderscoredKey(string $keyName): string
    {
        /* Replace capital letters with -capital  */
        $keyName = self::preg_replace_string('~([A-Z][a-z])~', '_$1', $keyName);

        /* Replace number letters with -number  */
        $keyName = self::preg_replace_string('~([A-Za-z])([0-9])~', '$1_$2', $keyName);
        $keyName = self::preg_replace_string('~([0-9])([A-Za-z])~', '$1_$2', $keyName);

        /* Replace all - to _ */
        $keyName = str_replace('-', '_', $keyName);

        /* Replace doubled __ */
        $keyName = self::preg_replace_string('~_+~', '_', $keyName);

        /* Remove _ at the beginning */
        $keyName = self::preg_replace_string('~^_~', '', $keyName);

        /* Transform all letters to upper */
        return strtoupper($keyName);
    }

    /**
     * Removes quotes from string.
     *
     * @param string $string $string
     * @return string
     * @throws PHPVaultNullException
     */
    public static function removeQuotes(string $string): string
    {
        return self::preg_replace_string('~^[\'"]?(.*?)[\'"]?$~', '$1', $string);
    }

    /**
     * Removes quotes from string and decrypt if needed.
     *
     * @param PHPVault $phpVaultCore
     * @param string|null $string $string
     * @param string|null $action
     * @param string|null $nonce
     * @return string|null
     * @throws SodiumException
     */
    public static function convertString(PHPVault $phpVaultCore, ?string $string, string $action = null, string $nonce = null): ?string
    {
        switch ($action) {
            case Reader::ACTION_ENCRYPT:
                return self::convertStringEncrypt($phpVaultCore, $string, $nonce);

            case Reader::ACTION_DECRYPT:
                return self::convertStringDecrypt($phpVaultCore, $string);

            default:
                return self::convertStringRaw($phpVaultCore, $string);
        }
    }

    /**
     * Removes quotes from string and decrypt if needed.
     *
     * @param PHPVault $phpVaultCore
     * @param string|null $string $string
     * @return string|null
     */
    public static function convertStringRaw(PHPVault $phpVaultCore, ?string $string): ?string
    {
        if ($string === null) {
            return null;
        }

        return self::removeQuotes($string);
    }

    /**
     * Removes quotes from string and decrypt if needed.
     *
     * @param PHPVault $phpVaultCore
     * @param string|null $string $string
     * @param string|null $nonce
     * @return string|null
     * @throws SodiumException
     * @throws Exception
     */
    public static function convertStringEncrypt(PHPVault $phpVaultCore, ?string $string, string $nonce = null): ?string
    {
        if ($string === null) {
            return null;
        }

        $string = self::removeQuotes($string);

        return $phpVaultCore->getEncrypter()->encrypt($string, $nonce);
    }

    /**
     * Removes quotes from string and decrypt if needed.
     *
     * @param PHPVault $phpVaultCore
     * @param string|null $string $string
     * @return string|null
     * @throws SodiumException
     * @throws Exception
     */
    public static function convertStringDecrypt(PHPVault $phpVaultCore, ?string $string): ?string
    {
        if ($string === null) {
            return null;
        }

        $string = self::removeQuotes($string);

        return $phpVaultCore->getDecrypter()->decrypt($string);
    }
}

