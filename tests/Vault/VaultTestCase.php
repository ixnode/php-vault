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

namespace Test\Ixnode\PhpVault\Vault;

use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\PHPVault;
use SodiumException;

class VaultTestCase extends TestCase
{
    protected static PHPVault $core;

    protected static string $publicKey = 'rzgp2/3Rtg8t6q/spiMrcEZq7cG75o1qsR/Kux/OC1E=';

    protected static string $privateKey = 'o8aZw6FIZmSMZq/89DNgxpNZHcgMbEOiU+1TMhNntb4=';

    protected static string $nonce = '57nrsXGZtxzD5PtRygZAy9Nr7PSCLFse';

    /**
     * Setup routines for the tests.
     * @throws SodiumException
     */
    public static function setUpBeforeClass(): void
    {
        self::$core = new PHPVault(false, self::$privateKey);
    }
}
