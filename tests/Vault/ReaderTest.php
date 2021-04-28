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

use Ixnode\PhpVault\Vault\KeyValuePair;
use Ixnode\PhpVault\Vault\Vault;
use Ixnode\PhpVault\Vault\Reader;
use Exception;
use SodiumException;

final class ReaderTest extends VaultTestCase
{
    /**
     * Test reader class exists.
     *
     * @return void
     * @throws Exception
     */
    public function testReaderExists(): void
    {
        /* Arrange */
        $expected = Reader::class;

        /* Act */
        /* nothing to do */

        /* Assert */
        $this->assertClassHasAttribute('reader', Vault::class);
        $this->assertTrue(method_exists(Vault::class, 'getReader'), 'Class Vault does not have method getReader.');
        $this->assertInstanceOf($expected, self::$phpVaultCoreV1->getVault()->getReader());
    }



    /**
     * Test vault reader array.
     * - Decrypted to Decrypted
     *
     * @dataProvider dataProviderArrayFromDecrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws SodiumException
     */
    public function testReaderArrayFromDecryptedToDecrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $decrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $actual = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_DECRYPTED, Reader::OUTPUT_TO_DECRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test vault reader array.
     * - Encrypted to Encrypted
     *
     * @dataProvider dataProviderArrayFromEncrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws Exception
     */
    public function testReaderArrayFromEncryptedToEncrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $encrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $actual = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_ENCRYPTED, READER::OUTPUT_TO_ENCRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test vault reader array.
     * - Decrypted to Encrypted
     *
     * @dataProvider dataProviderArrayFromDecrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws Exception
     */
    public function testReaderArrayFromDecryptedToEncrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $encrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $actual = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, READER::LOAD_FROM_DECRYPTED, READER::OUTPUT_TO_ENCRYPTED, self::$nonce);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test vault reader array.
     * - Encrypted to Decrypted
     *
     * @dataProvider dataProviderArrayFromEncrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws Exception
     */
    public function testReaderArrayFromEncryptedToDecrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $decrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $actual = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_ENCRYPTED, READER::OUTPUT_TO_DECRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }



    /**
     * Test add array to vault.
     * - Decrypted to Decrypted
     *
     * @dataProvider dataProviderArrayFromDecrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testReaderAddArrayToVaultFromDecryptedToDecrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $combined;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $array = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_DECRYPTED, Reader::OUTPUT_TO_DECRYPTED);
        self::$phpVaultCoreV1->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$phpVaultCoreV1->getVault()->getAllKeyValuePairs(true, Reader::OUTPUT_TO_DECRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test add array to vault.
     * - Encrypted to Encrypted
     *
     * @dataProvider dataProviderArrayFromEncrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testReaderAddArrayToVaultFromEncryptedToEncrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $encrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $array = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_ENCRYPTED);
        self::$phpVaultCoreV1->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$phpVaultCoreV1->getVault()->getAllKeyValuePairs(true, Reader::OUTPUT_TO_ENCRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test add array to vault.
     * - Decrypted to Encrypted
     *
     * @dataProvider dataProviderArrayFromDecrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testReaderAddArrayToVaultFromDecryptedToEncrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $encrypted;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $array = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_DECRYPTED, Reader::OUTPUT_TO_ENCRYPTED, self::$nonce);
        self::$phpVaultCoreV1->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$phpVaultCoreV1->getVault()->getAllKeyValuePairs(true, Reader::OUTPUT_TO_ENCRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test add array to vault.
     * - Encrypted to Decrypted
     *
     * @dataProvider dataProviderArrayFromEncrypted
     * @param string $stream
     * @param object[] $decrypted
     * @param object[] $encrypted
     * @param object[] $combined
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testReaderAddArrayToVaultFromEncryptedToDecrypted(string $stream, array $decrypted, array $encrypted, array $combined): void
    {
        /* Arrange */
        $expected = $combined;

        /* Act */
        self::$phpVaultCoreV1->clearVault();
        $array = self::$phpVaultCoreV1->getVault()->getReader()->convertStreamToKeyPairArray($stream, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_DECRYPTED);

        self::$phpVaultCoreV1->getVault()->getReader()->addArrayToVault($array, self::$nonce);
        $actual = self::$phpVaultCoreV1->getVault()->getAllKeyValuePairs(true, Reader::OUTPUT_TO_DECRYPTED);

        /* Assert */
        $this->assertEquals($expected, $actual);
    }



    /**
     * Provides some key variants to be converted.
     *
     * @return string[][]
     */
    public function dataProviderArrayFromDecrypted(): array
    {
        return $this->convertConfig($this->getTestConfig(), 0);
    }

    /**
     * Provides some key variants to be converted.
     *
     * @return string[][]
     */
    public function dataProviderArrayFromEncrypted(): array
    {
        return $this->convertConfig($this->getTestConfig(), 1);
    }

    /**
     * Returns the test config.
     *
     * @return array[]
     */
    protected function getTestConfig(): array
    {
        return array(
            /* Simple number test with one entry. */
            array(

                ###> STREAM ###
                'TEST=123',
                ###< STREAM ###

                ###> STREAM ###
                'TEST=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray('TEST', array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                )
            ),

            /* Simple string test with one entry and without quotes. */
            array(

                ###> STREAM ###
                'TEST=abc',
                ###< STREAM ###

                ###> STREAM ###
                'TEST=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ==',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray('TEST', array('abc', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ==')),
                )
            ),

            /* Simple string test with one entry and quotes. */
            array(

                ###> STREAM ###
                'TEST="abc"',
                ###< STREAM ###

                ###> STREAM ###
                'TEST="WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ=="',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray('TEST', array('abc', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImRwYUp3OG9oekw5T0tDSFN2YW1Yb0hNZmhRPT0iXQ==')),
                )
            ),

            /* Simple number test with number variable. */
            array(

                ###> STREAM ###
                'TEST1=123',
                ###< STREAM ###

                ###> STREAM ###
                'TEST1=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray('TEST_1', array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                )
            ),

            /* Simple number test with two entries. */
            array(

                ###> STREAM ###
                'TEST_1=123'."\n".
                'TEST_2=456',
                ###< STREAM ###

                ###> STREAM ###
                'TEST_1=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='."\n".
                'TEST_2=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0=',
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray('TEST_1', array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==')),
                    'TEST_2' => $this->getConfigArray('TEST_2', array('456', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0=')),
                ),
            ),

            /* Simple number test with comment. */
            array(

                ###> STREAM ###
                '# A comment with some text.'."\n".
                'TEST=123',
                ###< STREAM ###

                ###> STREAM ###
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd'."\n".
                'TEST=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ==',
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(
                        'TEST',
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

                ###> STREAM ###
                "\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInN6RmtyVGxKODFFa0tWa1VvVnhsRlZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkdJPSJd'."\n".
                'TEST=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST' => $this->getConfigArray(
                        'TEST',
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

                ###> STREAM ###
                "\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ=='."\n".
                'TEST_1=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='."\n".
                "\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ=='."\n".
                'TEST_2=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0='."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(
                        'TEST_1',
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text 123.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ==')
                    ),
                    'TEST_2' => $this->getConfigArray(
                        'TEST_2',
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

                ###> STREAM ###
                "\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ=='."\n".
                'TEST_1=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='."\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ=='."\n".
                'TEST_2=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0='."\n".
                "\n".
                '# WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJhb2hRVWRhMjBWUDNGYWVtbWVyNjFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5T3I1bVAiXQ=='."\n".
                'TEST_3="WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=="'."\n".
                '#WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInVENUhYckpyRUFQTjdwbGtLZkl0aTFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd6WTljT1AiXQ=='."\n".
                'TEST_4=WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=='."\n".
                "\n",
                ###< STREAM ###

                array(
                    'TEST_1' => $this->getConfigArray(
                        'TEST_1',
                        array('123', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInF1eExIdHVmaVc1UWJzQ3crcUVrTlNOUDFRPT0iXQ=='),
                        array('A comment with some text 123.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJSN1RwRzE4WmNFZUE3OHRTNjhmaFZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5SXBaT1AiXQ==')
                    ),
                    'TEST_2' => $this->getConfigArray(
                        'TEST_2',
                        array('456', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlFDRXh2T1djZW5TMkp2TGdhaFwvQnBpWkkwQT09Il0='),
                        array('A comment with some text 456.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInFVZDZNR3dOZ0NaU0p5U0t6SHBndVZOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5Tm9wYVAiXQ==')
                    ),
                    'TEST_3' => $this->getConfigArray(
                        'TEST_3',
                        array('This is a secure value.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=='),
                        array('A comment with some text 789.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIlJhb2hRVWRhMjBWUDNGYWVtbWVyNjFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd5T3I1bVAiXQ==')
                    ),
                    'TEST_4' => $this->getConfigArray(
                        'TEST_4',
                        array('This is a secure value.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIkc5SzhXTDJyM01ycW0rdFpkd1FwdzBZVmo1MWwxeU5VcjZcLzk2XC9tVEN5MjVTMHFcL09mQVMiXQ=='),
                        array('A comment with some text abc.', 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsInVENUhYckpyRUFQTjdwbGtLZkl0aTFOZGhZRW8welVhdXFcLzU1KzZPV1R2MlVFN3pPUEJFWkd6WTljT1AiXQ==')
                    ),
                ),
            ),
        );
    }

    /**
     * Separates the decrypted and encrypted part to two different arrays of given config.
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
     *
     * @param array[] $config
     * @param int $number
     * @return array[]
     */
    protected function convertConfig(array $config, int $number): array
    {
        array_walk($config, function (&$item) use ($number) {
            $item = array(
                $item[$number],
                array_map(function ($array) {
                    return $array['decrypted'];
                }, $item[2]),
                array_map(function ($array) {
                    return $array['encrypted'];
                }, $item[2]),
                array_map(function ($array) {
                    return $array['combined'];
                }, $item[2]),
            );
        });

        return $config;
    }

    /**
     * Returns a config array from given values and descriptions.
     *
     * @param string[] $value
     * @param string[]|null $description
     * @return object[]
     */
    protected function getConfigArray(string $name, array $value, array $description = null): array
    {
        return array(
            'decrypted' => new KeyValuePair($name, null, null, $value[0], $description === null ? null : $description[0]),
            'encrypted' => new KeyValuePair($name, $value[1], $description === null ? null : $description[1]),
            'combined'  => new KeyValuePair($name, $value[1], $description === null ? null : $description[1], $value[0], $description === null ? null : $description[0]),
        );
    }
}
