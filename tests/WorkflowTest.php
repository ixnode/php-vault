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

namespace Test\Ixnode\PhpVault;

use Ahc\Cli\IO\Interactor;
use Exception;
use Ixnode\PhpVault\Command\GenerateKeysCommand;
use Ixnode\PhpVault\Command\TestCommand;
use Ixnode\PhpVault\Logger\Logger;
use Ixnode\PhpVault\PHPVault;
use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\Cli;

final class WorkflowTest extends TestCase
{
    const TEMP_PREFIX = 'php-vault';

    const PATH_WORKING = '.working';

    const PATH_KEYS = 'keys';

    const PATH_TMP = '_tmp';

    const PATH_ENV_ENC = '.env.enc';

    const PATH_ENV = '.env';

    const PATH_ENV_2_ENC = '.env2.enc';

    const PATH_ENV_2 = '.env2';

    const PATH_EXECUTE_PHP_VAULT_PATH = 'vendor/bin/php-vault';

    const VALUE_USER = 'secret.user';

    const VALUE_PASS = 'secret.pass';

    const VALUE_HOST = 'secret.host';

    const VALUE_NAME = 'secret.name';

    /**
     * 01) Check help.
     *
     * @return void
     * @throws Exception
     */
    public function testHelp(): void
    {
        /* Arrange */
        $command = sprintf('%s --help', self::PATH_EXECUTE_PHP_VAULT_PATH);
        $search = sprintf('version %s', PHPVault::VERSION);

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
    }

    /**
     * 02) Check no key loaded (Expected no one).
     *
     * @return void
     * @throws Exception
     */
    public function testNoKeyLoaded(): void
    {
        /* Arrange */
        $command = sprintf('%s i', self::PATH_EXECUTE_PHP_VAULT_PATH);
        $search = 'No key was loaded.';

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
    }

    /**
     * 03) Check empty key folder.
     *
     * @return void
     * @throws Exception
     */
    public function testEmptyKeyFolder(): void
    {
        /* Arrange */
        $pathAbsoluteKeys = self::getPathAbsoluteKeys();

        /* Act */
        /* Nothing to do. */

        /* Assert */
        $this->assertTrue(!file_exists($pathAbsoluteKeys));
    }

    /**
     * 04) Generates a private public key pair.
     *
     * @return void
     * @throws Exception
     */
    public function testGenerateKeys(): void
    {
        /* Arrange */
        $pathAbsoluteKeys = self::getPathAbsoluteKeys();
        $command = sprintf('%s gk --persist %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteKeys);
        $search = 'The key pair is written to folder';

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
        $this->assertTrue(file_exists($pathAbsoluteKeys));
    }

    /**
     * 05) Check that the public key will be loaded.
     *
     * @return void
     * @throws Exception
     */
    public function testPublicKeyLoaded(): void
    {
        /* Arrange */
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $command = sprintf('%s i --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsolutePublicKey);
        $searches = ['A public key was loaded', 'The key was loaded from given file', ];

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        foreach ($searches as $search) {
            $this->assertIsInt(strpos($output, $search));
        }
    }

    /**
     * 06) Create .env.enc file with public key.
     *
     * @return void
     * @throws Exception
     */
    public function testSetCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEnvEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $commands = [
            sprintf('%s set %s DB_USER %s "DB Configs" --public-key %s --create', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, self::VALUE_USER, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_PASS %s --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, self::VALUE_PASS, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_HOST %s --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, self::VALUE_HOST, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_NAME %s --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, self::VALUE_NAME, $pathAbsolutePublicKey),
        ];
        $search = 'The file was successfully written to';

        /* Act */
        $outputs = [];
        foreach ($commands as $command) {
            $outputs[] = $this->executeCommand($command);
        }

        /* Assert */
        foreach ($outputs as $output) {
            $this->assertIsInt(strpos($output, $search));
        }
    }

    /**
     * 07) Test display command with public key (encrypted content).
     *
     * @return void
     * @throws Exception
     */
    public function testDisplayEncryptedCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEnvEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $command = sprintf('%s display %s --load-encrypted --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, $pathAbsolutePublicKey);
        $overheadLines = 5;
        $expectedEntries = 4;

        /* Act */
        $output = $this->executeCommand($command);
        $actualEntries = count(explode(Logger::LB, $output)) - $overheadLines;

        /* Assert */
        $this->assertSame($expectedEntries, $actualEntries);
    }

    /**
     * 08) Check that the private key will be loaded.
     *
     * @return void
     * @throws Exception
     */
    public function testPrivateKeyLoaded(): void
    {
        /* Arrange */
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PRIVATE_KEY);
        $command = sprintf('%s i --private-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsolutePublicKey);
        $searches = ['A private key was loaded', 'The key was loaded from given file', ];

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        foreach ($searches as $search) {
            $this->assertIsInt(strpos($output, $search));
        }
    }

    /**
     * 09) Test display command with private key (encrypted content to decrypted content).
     *
     * @throws Exception
     */
    public function testDisplayDecryptedCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEnvEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsolutePrivateKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PRIVATE_KEY);
        $command = sprintf('%s display %s --load-encrypted --display-decrypted --private-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, $pathAbsolutePrivateKey);
        $overheadLines = 5;
        $expectedEntries = 4;
        $searches = [self::VALUE_USER, self::VALUE_PASS, self::VALUE_HOST, self::VALUE_NAME, ];

        /* Act */
        $output = $this->executeCommand($command);
        $actualEntries = count(explode(Logger::LB, $output)) - $overheadLines;

        /* Assert */
        $this->assertSame($expectedEntries, $actualEntries);
        foreach ($searches as $search) {
            $this->assertIsInt(strpos($output, $search));
        }
    }

    /**
     * 10) Test decrypt file command with private key.
     *
     * @throws Exception
     */
    public function testDecryptFileCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEnvEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsoluteEnvFile = self::getPathAbsoluteWorking(self::PATH_ENV);
        $pathAbsolutePrivateKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PRIVATE_KEY);
        $command = sprintf('%s decrypt-file %s --private-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnvEncFile, $pathAbsolutePrivateKey);
        $searches = [self::VALUE_USER, self::VALUE_PASS, self::VALUE_HOST, self::VALUE_NAME, ];
        $searchCommand = 'The file was successfully written to';

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $searchCommand));
        $this->assertTrue(file_exists($pathAbsoluteEnvFile));
        $envFileContent = file_get_contents($pathAbsoluteEnvFile) ?: "";
        foreach ($searches as $search) {
            $this->assertIsInt(strpos($envFileContent, $search));
        }
    }

    /**
     * 11) Copy .env to .env2
     *
     * @throws Exception
     */
    public function testCopyEnvToEnv2(): void
    {
        /* Arrange */
        $pathAbsoluteEnvFile = self::getPathAbsoluteWorking(self::PATH_ENV);
        $pathAbsoluteEnv2File = self::getPathAbsoluteWorking(self::PATH_ENV_2);

        /* Act */
        copy($pathAbsoluteEnvFile, $pathAbsoluteEnv2File);

        /* Assert */
        $this->assertTrue(file_exists($pathAbsoluteEnv2File));
    }

    /**
     * 12) Test encrypt file command with public key.
     *
     * @throws Exception
     */
    public function testEncryptFileCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEnv2EncFile = self::getPathAbsoluteWorking(self::PATH_ENV_2_ENC);
        $pathAbsoluteEnv2File = self::getPathAbsoluteWorking(self::PATH_ENV_2);
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $command = sprintf('%s encrypt-file %s --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEnv2File, $pathAbsolutePublicKey);
        $searchCommand = 'The file was successfully written to';
        $overheadLines = 4; /* One comment, three empty lines → four */
        $expectedEntries = 4;

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $searchCommand));
        $this->assertTrue(file_exists($pathAbsoluteEnv2EncFile));

        /* Act */
        $envFileContent = file_get_contents($pathAbsoluteEnv2EncFile) ?: "";
        $actualEntries = count(explode(Logger::LB, $envFileContent)) - $overheadLines;

        /* Assert */
        $this->assertEquals($expectedEntries, $actualEntries);
    }

    /**
     * Tidy up temporary files.
     *
     * - Delete keys.a
     * - Delete created files and folders.
     *
     * @return void
     * @throws Exception
     */
    public static function tearDownAfterClass(): void
    {
        $pathAbsoluteWorking = self::getPathAbsoluteWorking();

        /* Get absolute path to ppk folder */
        self::deleteFoldersAndFiles($pathAbsoluteWorking);

        /* An error occurred while trying to delete the ppk folder */
        if (file_exists($pathAbsoluteWorking)) {
            throw new Exception(sprintf('Unable to delete folder "%s"', $pathAbsoluteWorking));
        }
    }

    /**
     * Deletes the given directory including its files and directories.
     *
     * @param string $directory
     */
    protected static function deleteFoldersAndFiles(string $directory): void
    {
        /* Get all files and folders except . and .. */
        $scannedDirectories = scandir($directory) ?: [];

        /* Remove . and .. folders */
        $files = array_diff($scannedDirectories, ['.', '..']);

        /* Delete each file or folder. */
        foreach ($files as $file) {
            if (is_dir("$directory/$file")) {
                /* Delete folder. */
                self::deleteFoldersAndFiles("$directory/$file");
            } else {
                /* Delete file. */
                unlink("$directory/$file");
            }
        }

        /* Delete given directory. */
        rmdir($directory);
    }

    /**
     * Executes the given command.
     *
     * @param string $command
     * @return string
     * @throws Exception
     */
    protected function executeCommand(string $command): string
    {
        $pathAbsoluteTemporary = self::getPathAbsoluteTemporary();

        /* Create temporary path if it does not exists. */
        if (!file_exists($pathAbsoluteTemporary)) {
            mkdir($pathAbsoluteTemporary, 0777, true);
        }

        /* Builds path to new writer */
        $pathWriter = tempnam($pathAbsoluteTemporary, self::TEMP_PREFIX);
        if ($pathWriter === false) {
            return '';
        }

        /* Builds new interactor */
        $interactor = new Interactor(null, $pathWriter);

        /* Builds cli command with one exit handler. */
        $cli = new Cli($command, $interactor, function ($exitCode = 0) { });
        $cli->handle();

        /* Gets all contents from writer. */
        $output = file_get_contents($pathWriter);

        /* Return content from writer. */
        return $output === false ? '' : $output;
    }

    /**
     * Returns the root of this project.
     *
     * @return string
     * @throws Exception
     */
    public static function getPathAbsoluteRootComposerJson(): string
    {
        $base = new TestCommand('test');
        return $base->getComposerJsonRootPath();
    }

    /**
     * Returns an absolute path of given fs elements.
     *
     * @return string
     * @throws Exception
     */
    public static function getPathAbsolute(): string
    {
        /* Get all given fs elements. */
        $fileSystemElements = func_get_args();

        /* Adds the root path to the beginning. */
        array_unshift($fileSystemElements, self::getPathAbsoluteRootComposerJson());

        return implode(DIRECTORY_SEPARATOR, $fileSystemElements);
    }

    /**
     * Returns an absolute path of given fs elements with .working path at the beginning.
     *
     * @return string
     */
    public static function getPathAbsoluteWorking(): string
    {
        /* Get all given fs elements. */
        $fileSystemElements = func_get_args();

        /* Adds working path to the beginning. */
        array_unshift($fileSystemElements, self::PATH_WORKING);

        /* Calls the static method getPathAbsolute */
        return call_user_func_array(array(self::class, 'getPathAbsolute'), $fileSystemElements);
    }

    /**
     * Returns an absolute path of given fs elements with .keys path at the beginning.
     *
     * @return string
     */
    public static function getPathAbsoluteKeys(): string
    {
        /* Get all given fs elements. */
        $fileSystemElements = func_get_args();

        /* Adds working path to the beginning. */
        array_unshift($fileSystemElements, self::PATH_KEYS);

        /* Calls the static method getPathAbsolute */
        return call_user_func_array(array(self::class, 'getPathAbsoluteWorking'), $fileSystemElements);
    }

    /**
     * Returns an absolute path of given fs elements with temporary path at the beginning.
     *
     * @return string
     */
    public static function getPathAbsoluteTemporary(): string
    {
        /* Get all given fs elements. */
        $fileSystemElements = func_get_args();

        /* Adds working path to the beginning. */
        array_unshift($fileSystemElements, self::PATH_TMP);

        /* Calls the static method getPathAbsolute */
        return call_user_func_array(array(self::class, 'getPathAbsoluteWorking'), $fileSystemElements);
    }
}
