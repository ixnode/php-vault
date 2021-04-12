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
     * @param array $decrypted
     * @param array $encrypted
     */
    public function testReaderArray(string $stream, array $decrypted, array $encrypted)
    {
        /* Arrange */
        $expected = $decrypted;

        /* Act */
        self::$core->clearVault();
        $actual = self::$core->getVault()->getReader()->convertStreamToArray($stream);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test add array to vault encrypted.
     *
     * @dataProvider dataProviderArray
     * @param string $stream
     * @param array $decrypted
     * @param array $encrypted
     * @throws SodiumException
     */
    public function testReaderAddArrayToVaultEncrypted(string $stream, array $decrypted, array $encrypted)
    {
        /* Arrange */
        $expected = $encrypted;

        /* Act */
        self::$core->clearVault();
        $array = self::$core->getVault()->getReader()->convertStreamToArray($stream);
        self::$core->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$core->getVault()->getAll(true, true, false);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test add array to vault decrypted.
     *
     * @dataProvider dataProviderArray
     * @param string $stream
     * @param array $decrypted
     * @param array $encrypted
     * @throws SodiumException
     */
    public function testReaderAddArrayToVaultDecryted(string $stream, array $decrypted, array $encrypted)
    {
        /* Arrange */
        $expected = $decrypted;

        /* Act */
        self::$core->clearVault();
        $array = self::$core->getVault()->getReader()->convertStreamToArray($stream);
        self::$core->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$core->getVault()->getAll(true, true, true);

        /* Assert */
        $this->assertEquals($expected, $actual);
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
                    'TEST' => (object) [
                        'value' => '123',
                        'description' => null,
                    ],
                ),
                array(
                    'TEST' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => null,
                    ],
                )
            ),
            array(

                ###> STREAM ###
                "TEST1=123",
                ###< STREAM ###

                array(
                    'TEST_1' => (object) [
                        'value' => '123',
                        'description' => null,
                    ],
                ),
                array(
                    'TEST_1' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => null,
                    ],
                )
            ),
            array(

                ###> STREAM ###
                "TEST_1=123\n".
                "TEST_2=456",
                ###< STREAM ###

                array(
                    'TEST_1' => (object) [
                        'value' => '123',
                        'description' => null,
                    ],
                    'TEST_2' => (object) [
                        'value' => '456',
                        'description' => null,
                    ],
                ),
                array(
                    'TEST_1' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => null,
                    ],
                    'TEST_2' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0=',
                        'description' => null,
                    ],
                )
            ),
            array(

                ###> STREAM ###
                "# A comment with some text.\n".
                "TEST=123",
                ###< STREAM ###

                array(
                    'TEST' => (object) [
                        'value' => '123',
                        'description' => 'A comment with some text.',
                    ],
                ),
                array(
                    'TEST' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd',
                    ],
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
                    'TEST' => (object) [
                        'value' => '123',
                        'description' => 'A comment with some text.',
                    ],
                ),
                array(
                    'TEST' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd',
                    ],
                )
            ),
            array(

                ###> STREAM ###
                "\n".
                "# A comment with some text 123.\n".
                "TEST_1=123\n".
                "\n".
                "# A comment with some text 456.\n".
                "TEST_2=456\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST_1' => (object) [
                        'value' => '123',
                        'description' => 'A comment with some text 123.',
                    ],
                    'TEST_2' => (object) [
                        'value' => '456',
                        'description' => 'A comment with some text 456.',
                    ],
                ),
                array(
                    'TEST_1' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                        'description' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ==',
                    ],
                    'TEST_2' => (object) [
                        'value' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0=',
                        'description' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ==',
                    ],
                )
            ),
        );
    }
}
