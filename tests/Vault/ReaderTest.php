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

use Ixnode\PhpVault\Vault\Vault;
use Ixnode\PhpVault\Vault\Reader;
use Test\Ixnode\PhpVault\Vault\VaultTestCase;

final class ReaderTest extends VaultTestCase
{
    /**
     * Test reader class exists.
     *
     * @throws Exception
     */
    public function testReaderExists()
    {
        /* Arrange */
        $expected = Reader::class;

        /* Act */
        /* nothing to do */

        /* Assert */
        $this->assertClassHasAttribute('reader', Vault::class);
        $this->assertTrue(method_exists(Vault::class, 'getReader'), 'Class Vault does not have method getReader.');
        $this->assertInstanceOf($expected, self::$core->getVault()->getReader());
    }

    /**
     * Test vault reader array.
     *
     * @dataProvider dataProviderArray
     * @param string $stream
     * @param array $array
     */
    public function testReaderArray(string $stream, array $array)
    {
        /* Arrange */
        $expected = $array;

        /* Act */
        $actual = self::$core->getVault()->getReader()->convertStreamToArray($stream);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Provides some key variants to be converted.
     *
     * @return string[][]
     */
    public function dataProviderArray(): array
    {
        return array(
            array(

                ###> STREAM ###
                "TEST=123",
                ###< STREAM ###

                array(
                    'TEST' => array(
                        'value' => '123',
                        'description' => null,
                    ),
                )
            ),
            array(

                ###> STREAM ###
                "TEST1=123\n".
                "TEST2=456",
                ###< STREAM ###

                array(
                    'TEST1' => array(
                        'value' => '123',
                        'description' => null,
                    ),
                    'TEST2' => array(
                        'value' => '456',
                        'description' => null,
                    ),
                )
            ),
            array(

                ###> STREAM ###
                "# A comment with some text.\n".
                "TEST=123",
                ###< STREAM ###

                array(
                    'TEST' => array(
                        'value' => '123',
                        'description' => 'A comment with some text.',
                    ),
                )
            ),
            array(

                ###> STREAM ###
                "\n".
                "# A comment with some text.\n".
                "TEST=123\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST' => array(
                        'value' => '123',
                        'description' => 'A comment with some text.',
                    ),
                )
            ),
            array(

                ###> STREAM ###
                "\n".
                "# A comment with some text 123.\n".
                "TEST1=123\n".
                "\n".
                "# A comment with some text 456.\n".
                "TEST2=456\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST1' => array(
                        'value' => '123',
                        'description' => 'A comment with some text 123.',
                    ),
                    'TEST2' => array(
                        'value' => '456',
                        'description' => 'A comment with some text 456.',
                    ),
                )
            ),
        );
    }
}
