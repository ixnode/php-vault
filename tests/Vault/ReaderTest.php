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
        $testConfig = array(
            /* Simple number test with one entry. */
            array(

                ###> STREAM ###
                'TEST=123',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                )
            ),

            /* Simple string test with one entry and without quotes. */
            array(

                ###> STREAM ###
                'TEST=abc',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(array('abc', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ==')),
                )
            ),

            /* Simple string test with one entry and quotes. */
            array(

                ###> STREAM ###
                'TEST="abc"',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(array('abc', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ==')),
                )
            ),

            /* Simple number test with number variable. */
            array(

                ###> STREAM ###
                'TEST1=123',
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                )
            ),

            /* Simple number test with two entries. */
            array(

                ###> STREAM ###
                'TEST_1=123'."\n".
                'TEST_2=456',
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                    'TEST_2' => $this->getConfigArray(array('456', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0=')),
                ),
            ),

            /* Simple number test with comment. */
            array(

                ###> STREAM ###
                '# A comment with some text.'."\n".
                'TEST=123',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd')
                    ),
                ),
            ),

            /* Simple number test with comment and unnecessary extra lines.  */
            array(

                ###> STREAM ###
                "\n".
                '# A comment with some text.'."\n".
                'TEST=123'."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd')
                    ),
                ),
            ),

            /* Simple number test with comment and two entries. */
            array(

                ###> STREAM ###
                "\n".
                '# A comment with some text 123.'."\n".
                'TEST_1=123'."\n".
                "\n".
                '# A comment with some text 456.'."\n".
                'TEST_2=456'."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text 123.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ==')
                    ),
                    'TEST_2' => $this->getConfigArray(
                        array('456', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0='),
                        array('A comment with some text 456.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ==')
                    ),
                ),
            ),

            /* Complex test with comments and multiple entries and some "mistakes". */
            array(

                ###> STREAM ###
                "\n".
                '# A comment with some text 123.'."\n".
                'TEST_1=123'."\n".
                '# A comment with some text 456.'."\n".
                'TEST_2=456'."\n".
                "\n".
                '# A comment with some text 789.'."\n".
                'TEST_3="This is a secure value."'."\n".
                '#A comment with some text abc.'."\n".
                'TEST_4=This is a secure value.'."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text 123.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ==')
                    ),
                    'TEST_2' => $this->getConfigArray(
                        array('456', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0='),
                        array('A comment with some text 456.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ==')
                    ),
                    'TEST_3' => $this->getConfigArray(
                        array('This is a secure value.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=='),
                        array('A comment with some text 789.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJhb2hRVWRhMjBWUDNGYWVtbWVyNjFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5T3I1bVAiXQ==')
                    ),
                    'TEST_4' => $this->getConfigArray(
                        array('This is a secure value.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=='),
                        array('A comment with some text abc.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInVENUhYckpyRUFQTjdwbGtLZkl0aTFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd6WTljT1AiXQ==')
                    ),
                ),
            ),
        );

        /* Separate decrypted and encrypted part to two different arrays.
         * Convert 2 dimensional array into a 3 dimensional array:
         *
         * ---
         * array(
         *     string,                                                     # SAME STRING
         *     {
         *         a => {'decrypted' => ...1..., 'encrypted' => ...2...},  # COMBINED DECRYPTED AND ENCRYPTED STRING
         *         b => {'decrypted' => ...3..., 'encrypted' => ...4...},  # COMBINED DECRYPTED AND ENCRYPTED STRING
         *         ...
         *     }
         * )
         *
         * =>
         *
         * array(
         *     string,                             # SAME STRING
         *     {a => ...1..., b => ...3..., ...},  # DECRYPTED PART
         *     {a => ...2..., b => ...4..., ...}   # ENCRYPTED PART
         * )
         * ---
         */
        array_walk($testConfig, function(&$item) {
            $item = array(
                $item[0],
                array_map(function ($array) { return $array['decrypted']; }, $item[1]),
                array_map(function ($array) { return $array['encrypted']; }, $item[1]),
            );
        });

        /* Return converted string */
        return $testConfig;
    }

    protected function getConfigArray(array $value, array $description = null)
    {
        return array(
            'decrypted' => $this->getValueDescriptionObject($value[0], $description === null ? null : $description[0]),
            'encrypted' => $this->getValueDescriptionObject($value[1], $description === null ? null : $description[1]),
        );
    }

    /**
     * Returns a value description object (helper function).
     *
     * @param string $value
     * @param string|null $description
     * @return object
     */
    protected function getValueDescriptionObject(string $value, string $description = null): object
    {
        return (object) [
            'value' => $value,
            'description' => $description,
        ];
    }
}
