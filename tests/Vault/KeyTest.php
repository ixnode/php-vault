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

use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\Core;

final class KeyTest extends TestCase
{
    protected static Core $core;

    /**
     * Setup routines for the tests.
     */
    public static function setUpBeforeClass(): void
    {
        self::$core = new Core(true);
    }

    /**
     * Test and convert different key variants.
     *
     * @dataProvider dataProvider
     * @param string $key
     * @param string $expected
     */
    public function testKeys(string $key, string $expected)
    {
        /* Arrange */
        /* comes from @dataProvider */

        /* Act */
        $actual = self::$core->getVault()->getUnderscoredKey($key);

        /* Assert */
        $this->assertIsString($key);
        $this->assertIsString($expected);
        $this->assertIsString($actual);
        $this->assertSame($expected, $actual);
    }

    /**
     * Provides some key variants to be converted.
     *
     * @return string[][]
     */
    public function dataProvider(): array
    {
        return array(
            /* Basic keys */
            array('key', 'KEY'),
            array('KEY', 'KEY'),
            array('Key', 'KEY'),
            array('kEy', 'K_EY'),
            array('key123', 'KEY_123'),

            /* camelCase keys */
            array('keyValue', 'KEY_VALUE'),
            array('keyValueSecure', 'KEY_VALUE_SECURE'),

            /* PascalCase keys */
            array('KeyValue', 'KEY_VALUE'),
            array('KeyValueSecure', 'KEY_VALUE_SECURE'),
            array('KeyValueSecure123', 'KEY_VALUE_SECURE_123'),

            /* UNDER_SCORE keys */
            array('KEY_VALUE', 'KEY_VALUE'),
            array('KEY_VALUE_SECURE', 'KEY_VALUE_SECURE'),
            array('KEY_VALUE_123', 'KEY_VALUE_123'),
            array('KEY_VALUE123', 'KEY_VALUE_123'),
            array('KEY_VALUE123ABC', 'KEY_VALUE_123_ABC'),

            /* hyphen-keys */
            array('key-value', 'KEY_VALUE'),
            array('key-value-secure', 'KEY_VALUE_SECURE'),
            array('key-value-secure-123', 'KEY_VALUE_SECURE_123'),

            /* mixed keys */
            array('key-valueSecure', 'KEY_VALUE_SECURE'),
            array('KeyValue-secure', 'KEY_VALUE_SECURE'),
            array('KeyValue-secure123', 'KEY_VALUE_SECURE_123'),
            array('KeyValue--_secure123', 'KEY_VALUE_SECURE_123'),
        );
    }
}
