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

use Ixnode\PhpVault\PHPVault;
use Ixnode\PhpVault\Vault\Reader;
use Ixnode\PhpVault\Vault\Vault;
use Ixnode\PhpVault\Vault\KeyValuePair;
use Exception;
use SodiumException;

final class VaultTest extends VaultTestCase
{
    const TEMPLATE_ENV_WITHOUT_DESCRIPTION = <<<TEXT
NAME_WITHOUT_ENCRYPTION="%s"
NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION="%s"
NAME_WITH_ENCRYPTION="%s"
NAME_WITH_ENCRYPTION_WITH_DESCRIPTION="%s"
NAME_WITH_AUTO_ENCRYPTION="%s"
NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION="%s"
NAME_NEW="%s"
TEXT;

    const TEMPLATE_ENV_WITH_DESCRIPTION = <<<TEXT
# %s
NAME_WITHOUT_ENCRYPTION="%s"

# %s
NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION="%s"

# %s
NAME_WITH_ENCRYPTION="%s"

# %s
NAME_WITH_ENCRYPTION_WITH_DESCRIPTION="%s"

# %s
NAME_WITH_AUTO_ENCRYPTION="%s"

# %s
NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION="%s"

# %s
NAME_NEW="%s"
TEXT;

    /**
     * Check some base things.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     */
    public function testBase(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = Vault::class;

        /* Act */
        /* nothing to do */

        /* Assert */
        $this->assertClassHasAttribute('vault', PHPVault::class);
        $this->assertTrue(method_exists(PHPVault::class, 'getVault'), 'Class Core does not have method getVault.');
        $this->assertInstanceOf($expected, self::$core->getVault());
    }

    /**
     * Test empty vault.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testEmptyVault(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = [];

        /* Act */
        $vault = self::$core->getVault()->getAllValuesFromVault();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test add method vault (without encryption).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testAddVault(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-without-encryption';
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = $data->getValueEncrypted();

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValueEncrypted = self::$core->getVault()->getKeyValuePairRaw($name)->getValueEncrypted();

        /* Assert */
        $this->assertSame($expected, $vaultValueEncrypted);
    }

    /**
     * Test add method vault (without encryption with description).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testAddVaultWithDescription(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-without-encryption-with-description';
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = new KeyValuePair(
            $name,
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted()
        );

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValueEncrypted = self::$core->getVault()->getKeyValuePairDecrypted($name);

        /* Assert */
        $this->assertEquals($expected, $vaultValueEncrypted);
    }

    /**
     * Test add method vault (with encryption).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testAddVaultEncryption(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-with-encryption';
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = $valueDecrypted;

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValue = self::$core->getVault()->getKeyValuePairRaw($name)->getValueEncrypted();
        $vaultValueDecrypted = self::$core->getDecrypter()->decrypt($vaultValue);

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption with description).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws SodiumException
     */
    public function testAddVaultEncryptionWithDescription(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-with-encryption-with-description';
        $valueEncrypted = $data->getValueEncrypted();
        $descriptionEncrypted = $data->getDescriptionEncrypted();
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = new KeyValuePair(
            $name,
            $valueEncrypted,
            $descriptionEncrypted,
            $valueDecrypted,
            $descriptionDecrypted
        );

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->getKeyValuePairDecrypted($name);

        /* Assert */
        $this->assertEquals($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws SodiumException
     */
    public function testAddVaultAutoEncryption(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-with-auto-encryption';
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = $valueDecrypted;

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->getKeyValuePairRaw($name)->getValueDecrypted();

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption with description).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws SodiumException
     */
    public function testAddVaultAutoEncryptionWithDescription(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-with-auto-encryption-with-description';
        $valueDecrypted = $data->getValueDecrypted();
        $descriptionDecrypted = $data->getDescriptionDecrypted();
        $expected = $valueDecrypted;

        /* Act */
        self::$core->getVault()->add($name, $valueDecrypted, $descriptionDecrypted, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->getKeyValuePairRaw($name)->getValueDecrypted();

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test get vault array.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetArray(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array(
            'name-without-encryption' => $data->getValueEncrypted(),
            'name-without-encryption-with-description' => $data->getValueEncrypted(),
            'name-with-encryption' => $data->getValueEncrypted(),
            'name-with-encryption-with-description' => $data->getValueEncrypted(),
            'name-with-auto-encryption' => $data->getValueEncrypted(),
            'name-with-auto-encryption-with-description' => $data->getValueEncrypted(),
        );

        /* Act */
        $vault = self::$core->getVault()->getAllValuesFromVault();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test get vault array decrypted.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetArrayDecrypted(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array(
            'name-without-encryption' => $data->getValueDecrypted(),
            'name-without-encryption-with-description' => $data->getValueDecrypted(),
            'name-with-encryption' => $data->getValueDecrypted(),
            'name-with-encryption-with-description' => $data->getValueDecrypted(),
            'name-with-auto-encryption' => $data->getValueDecrypted(),
            'name-with-auto-encryption-with-description' => $data->getValueDecrypted(),
        );

        /* Act */
        $vault = self::$core->getVault()->getAllValuesFromVaultDecrypted();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test get vault array decrypted.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetArrayDecryptedUnderscored(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
        );

        /* Act */
        $actual = self::$core->getVault()->getAllValuesFromVaultDecrypted(true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Test the $_ENV array to be empty.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     */
    public function testEmptyEnvArray(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array();

        /* Act */
        $actual = $_ENV;

        /* Assert */
        $this->assertSame($expected, $actual, '$_ENV seems not to be empty.');
    }

    /**
     * Test: Save vault to $_ENV.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testSaveEnvArray(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
        );

        /* Act */
        self::$core->getVault()->getWriter()->saveToEnv();
        $actual = $_ENV;

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Test: Save vault to $_SERVER.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testSaveServerArray(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
        );

        /* Act */
        self::$core->getVault()->getWriter()->saveToServer();
        $actual = $_SERVER;

        /* Assert */
        foreach ($expected as $key => $name) {
            $this->assertArrayHasKey($key, $actual);
            $this->assertSame($name, $actual[$key]);
        }
    }

    /**
     * Test: Adds new entry and saves vault to $_ENV.
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testAddAndSaveEnvArray(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $name = 'name-new';
        $value = $data2->getValueDecrypted();
        $description = $data2->getDescriptionDecrypted();
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION' => $data->getValueDecrypted(),
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => $data->getValueDecrypted(),
            'NAME_NEW' => $data2->getValueDecrypted(),
        );

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        self::$core->getVault()->getWriter()->saveToEnv();
        $actual = $_ENV;

        /* Assert */
        foreach ($expected as $key => $name) {
            $this->assertArrayHasKey($key, $actual);
            $this->assertSame($name, $actual[$key]);
        }
    }

    /**
     * Generates .env.secure file content (encrypted content).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetEnvContent(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITHOUT_DESCRIPTION,
            $data->getValueEncrypted(),
            $data->getValueEncrypted(),
            $data->getValueEncrypted(),
            $data->getValueEncrypted(),
            $data->getValueEncrypted(),
            $data->getValueEncrypted(),
            $data2->getValueEncrypted()
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString();

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env.secure file content with description (encrypted content).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetEnvContentWithDescription(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITH_DESCRIPTION,
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data->getDescriptionEncrypted(),
            $data->getValueEncrypted(),
            $data2->getDescriptionEncrypted(),
            $data2->getValueEncrypted()
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(Reader::OUTPUT_TO_ENCRYPTED, true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env file content (decrypted content).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetEnvContentDecrypted(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITHOUT_DESCRIPTION,
            $data->getValueDecrypted(),
            $data->getValueDecrypted(),
            $data->getValueDecrypted(),
            $data->getValueDecrypted(),
            $data->getValueDecrypted(),
            $data->getValueDecrypted(),
            $data2->getValueDecrypted()
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(Reader::OUTPUT_TO_DECRYPTED);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env file content (decrypted content).
     *
     * @dataProvider dataProvider
     * @param KeyValuePair $data
     * @param KeyValuePair $data2
     * @return void
     * @throws Exception
     */
    public function testGetEnvContentDecryptedWithDescription(KeyValuePair $data, KeyValuePair $data2): void
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITH_DESCRIPTION,
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data->getDescriptionDecrypted(),
            $data->getValueDecrypted(),
            $data2->getDescriptionDecrypted(),
            $data2->getValueDecrypted()
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(Reader::OUTPUT_TO_DECRYPTED, true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Returns an data provider.
     *
     * @return KeyValuePair[][]
     */
    public function dataProvider(): array
    {
        return array(
            array(
                'data' => new KeyValuePair(
                    'data',
                    'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImJFNXhROVBHUUN4K2FFdnJTY2hOSHlKTTFOMXhpMlpEOXJiUHpObWlQQTQ9Il0=',
                    'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIk1BdlVWQTRxaEpObllLODhvZTdqcVVZVmc4NHozendCcTYrK3Y2alZUWDJ2Q2hQcURkZFwvVkFuXC90OWZBaG1Lbk9mWFV5YW89Il0=',
                    '0123456789ABCDEF',
                    'The value 0123456789ABCDEF was given.'
                ),
                'data2' => new KeyValuePair(
                    'data2',
                    'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImVCMjM3YUJoOEdKbFlSTndOK1d2UUh3WWtjTXozendCcXc9PSJd',
                    'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIk5jTUNjbUJtQURJRyszSDVFcUh1QkZZWWxZMDMxeUFBcCtEZ3J2V0FXU2I4U2d1bExmbEpkV0k9Il0=',
                    'new-value',
                    'Description of new value.'
                ),
            )
        );
    }
}
