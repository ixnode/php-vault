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
use Ixnode\PhpVault\Vault\Vault;
use Exception;
use SodiumException;

final class VaultTest extends VaultTestCase
{
    protected static object $data;

    protected static object $data2;

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
     * Setup routines for the tests.
     * @throws SodiumException
     */
    public static function setUpBeforeClass(): void
    {
        self::$data = (object) [
            'value' => '0123456789ABCDEF',
            'description' => 'The value 0123456789ABCDEF was given.',
            'valueDecrypted' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImJFNXhROVBHUUN4K2FFdnJTY2hOSHlKTTFOMXhpMlpEOXJiUHpObWlQQTQ9Il0=',
            'descriptionDecrypted' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIk1BdlVWQTRxaEpObllLODhvZTdqcVVZVmc4NHozendCcTYrK3Y2alZUWDJ2Q2hQcURkZFwvVkFuXC90OWZBaG1Lbk9mWFV5YW89Il0='
        ];

        self::$data2 = (object) [
            'value' => 'new-value',
            'description' => 'Description of new value.',
            'valueDecrypted' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsImVCMjM3YUJoOEdKbFlSTndOK1d2UUh3WWtjTXozendCcXc9PSJd',
            'descriptionDecrypted' => 'WyI1N25yc1hHWnR4ekQ1UHRSeWdaQXk5TnI3UFNDTEZzZSIsIk5jTUNjbUJtQURJRyszSDVFcUh1QkZZWWxZMDMxeUFBcCtEZ3J2V0FXU2I4U2d1bExmbEpkV0k9Il0='
        ];

        parent::setUpBeforeClass();
    }

    /**
     * Check some base things.
     */
    public function testBase()
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
     * @throws Exception
     */
    public function testEmptyVault()
    {
        /* Arrange */
        $expected = [];

        /* Act */
        $vault = self::$core->getVault()->getAll();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test add method vault (without encryption).
     *
     * @throws Exception
     */
    public function testAddVault()
    {
        /* Arrange */
        $name = 'name-without-encryption';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = self::$data->valueDecrypted;

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValueEncrypted = self::$core->getVault()->get($name);

        /* Assert */
        $this->assertSame($expected, $vaultValueEncrypted);
    }

    /**
     * Test add method vault (without encryption with description).
     *
     * @throws Exception
     */
    public function testAddVaultWithDescription()
    {
        /* Arrange */
        $name = 'name-without-encryption-with-description';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = (object) [
            'value' => self::$data->valueDecrypted,
            'description' => self::$data->descriptionDecrypted,
        ];

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValueEncrypted = self::$core->getVault()->get($name, true);

        /* Assert */
        $this->assertEquals($expected, $vaultValueEncrypted);
    }

    /**
     * Test add method vault (with encryption).
     *
     * @throws SodiumException
     * @throws Exception
     */
    public function testAddVaultEncryption()
    {
        /* Arrange */
        $name = 'name-with-encryption';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = $value;

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValue = self::$core->getVault()->get($name);
        $vaultValueDecrypted = self::$core->getDecrypter()->decrypt($vaultValue);

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption with description).
     *
     * @throws SodiumException
     */
    public function testAddVaultEncryptionWithDescription()
    {
        /* Arrange */
        $name = 'name-with-encryption-with-description';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = (object) [
            'value' => $value,
            'description' => $description
        ];

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->decrypt($name, true);

        /* Assert */
        $this->assertEquals($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption).
     *
     * @throws SodiumException
     */
    public function testAddVaultAutoEncryption()
    {
        /* Arrange */
        $name = 'name-with-auto-encryption';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = $value;

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->decrypt($name);

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test add method vault (with auto encryption with description).
     *
     * @throws SodiumException
     */
    public function testAddVaultAutoEncryptionWithDescription()
    {
        /* Arrange */
        $name = 'name-with-auto-encryption-with-description';
        $value = self::$data->value;
        $description = self::$data->description;
        $expected = $value;

        /* Act */
        self::$core->getVault()->add($name, $value, $description, self::$nonce);
        $vaultValueDecrypted = self::$core->getVault()->decrypt($name);

        /* Assert */
        $this->assertSame($expected, $vaultValueDecrypted);
    }

    /**
     * Test get vault array.
     *
     * @throws Exception
     */
    public function testGetArray()
    {
        /* Arrange */
        $expected = array(
            'name-without-encryption' => self::$data->valueDecrypted,
            'name-without-encryption-with-description' => self::$data->valueDecrypted,
            'name-with-encryption' => self::$data->valueDecrypted,
            'name-with-encryption-with-description' => self::$data->valueDecrypted,
            'name-with-auto-encryption' => self::$data->valueDecrypted,
            'name-with-auto-encryption-with-description' => self::$data->valueDecrypted,
        );

        /* Act */
        $vault = self::$core->getVault()->getAll();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test get vault array decrypted.
     *
     * @throws Exception
     */
    public function testGetArrayDecrypted()
    {
        /* Arrange */
        $expected = array(
            'name-without-encryption' => self::$data->value,
            'name-without-encryption-with-description' => self::$data->value,
            'name-with-encryption' => self::$data->value,
            'name-with-encryption-with-description' => self::$data->value,
            'name-with-auto-encryption' => self::$data->value,
            'name-with-auto-encryption-with-description' => self::$data->value,
        );

        /* Act */
        $vault = self::$core->getVault()->getAllDecrypted();

        /* Assert */
        $this->assertSame($expected, $vault);
    }

    /**
     * Test get vault array decrypted.
     *
     * @throws Exception
     */
    public function testGetArrayDecryptedUnderscored()
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => self::$data->value,
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
        );

        /* Act */
        $actual = self::$core->getVault()->getAllDecrypted(true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Test the $_ENV array to be empty.
     */
    public function testEmptyEnvArray()
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
     * @throws Exception
     */
    public function testSaveEnvArray()
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => self::$data->value,
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
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
     * @throws Exception
     */
    public function testSaveServerArray()
    {
        /* Arrange */
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => self::$data->value,
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
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
     * @throws SodiumException
     * @throws Exception
     */
    public function testAddAndSaveEnvArray()
    {
        /* Arrange */
        $name = 'name-new';
        $value = self::$data2->value;
        $description = self::$data2->description;
        $expected = array(
            'NAME_WITHOUT_ENCRYPTION' => self::$data->value,
            'NAME_WITHOUT_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION' => self::$data->value,
            'NAME_WITH_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION' => self::$data->value,
            'NAME_WITH_AUTO_ENCRYPTION_WITH_DESCRIPTION' => self::$data->value,
            'NAME_NEW' => self::$data2->value,
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
     * @throws Exception
     */
    public function testGetEnvContent()
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITHOUT_DESCRIPTION,
            self::$data->valueDecrypted,
            self::$data->valueDecrypted,
            self::$data->valueDecrypted,
            self::$data->valueDecrypted,
            self::$data->valueDecrypted,
            self::$data->valueDecrypted,
            self::$data2->valueDecrypted
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString();

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env.secure file content with description (encrypted content).
     *
     * @throws Exception
     */
    public function testGetEnvContentWithDescription()
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITH_DESCRIPTION,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data->descriptionDecrypted,
            self::$data->valueDecrypted,
            self::$data2->descriptionDecrypted,
            self::$data2->valueDecrypted
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(false, true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env file content (decrypted content).
     *
     * @throws Exception
     */
    public function testGetEnvContentDecrypted()
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITHOUT_DESCRIPTION,
            self::$data->value,
            self::$data->value,
            self::$data->value,
            self::$data->value,
            self::$data->value,
            self::$data->value,
            self::$data2->value
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Generates .env file content (decrypted content).
     *
     * @throws Exception
     */
    public function testGetEnvContentDecryptedWithDescription()
    {
        /* Arrange */
        $expected = sprintf(
            self::TEMPLATE_ENV_WITH_DESCRIPTION,
            self::$data->description,
            self::$data->value,
            self::$data->description,
            self::$data->value,
            self::$data->description,
            self::$data->value,
            self::$data->description,
            self::$data->value,
            self::$data->description,
            self::$data->value,
            self::$data->description,
            self::$data->value,
            self::$data2->description,
            self::$data2->value
        );

        /* Act */
        $actual = self::$core->getVault()->getWriter()->getEnvString(true, true);

        /* Assert */
        $this->assertSame($expected, $actual);
    }
}
