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

use Ixnode\PhpVault\Vault\Vault;
use Ixnode\PhpVault\Vault\Writer;
use Exception;

final class WriterTest extends VaultTestCase
{
    /**
     * Test writer class exists.
     *
     * @return void
     * @throws Exception
     */
    public function testWriterExists(): void
    {
        /* Arrange */
        $expected = Writer::class;

        /* Act */
        /* nothing to do */

        /* Assert */
        $this->assertClassHasAttribute('writer', Vault::class);
        $this->assertTrue(method_exists(Vault::class, 'getWriter'), 'Class Vault does not have method getWriter.');
        $this->assertInstanceOf($expected, self::$core->getVault()->getWriter());
    }

    /**
     * Tests the key_writer.
     *
     * @param string $given
     * @param string $expected
     * @dataProvider dataProvider
     */
    public function testWriterKeyGenerator(string $given, string $expected): void
    {
        /* Arrange */
        /* Given from dataProvider */

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getPhpVaultEnvironmentKey($given);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Returns an data provider.
     *
     * @return array[]
     */
    public function dataProvider(): array
    {
        return [
            ['test', sprintf('%s%s', Writer::ENV_PREFIX, 'test')],
            ['DB_VALUE', sprintf('%s%s', Writer::ENV_PREFIX, 'DB_VALUE')],
            [sprintf('%s%s', Writer::ENV_PREFIX, 'DB_VALUE'), sprintf('%s%s', Writer::ENV_PREFIX, 'DB_VALUE')],
        ];
    }
}
