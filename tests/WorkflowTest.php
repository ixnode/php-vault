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
use Ixnode\PhpVault\Logger\Logger;
use Ixnode\PhpVault\PHPVault;
use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\Cli;
use Ixnode\PhpVault\Command\BaseCommand;

final class WorkflowTest extends TestCase
{
    const TEMP_PREFIX = 'php-vault';

    const PATH_WORKING = '.working';

    const PATH_KEYS = 'keys';

    const PATH_TMP = '_tmp';

    const PATH_ENV_ENC = '.env.enc';

    const PATH_ENV = '.env';

    const PATH_EXECUTE_PHP_VAULT_PATH = 'vendor/bin/php-vault';

    /**
     * 1) Check help.
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
     * 2) Check no key loaded (Expected no one).
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
     * 3) Check empty key folder.
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
     * 4) Generates a private public key pair.
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
     * 5) Check that the public key will be loaded.
     *
     * @return void
     * @throws Exception
     */
    public function testPublicKeyLoaded(): void
    {
        /* Arrange */
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $command = sprintf('%s i --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsolutePublicKey);
        $searches = ['Public key was loaded', 'The key was loaded from given file', ];

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        foreach ($searches as $search) {
            $this->assertIsInt(strpos($output, $search));
        }
    }

    /**
     * 6) Create .env.enc file with public key.
     *
     * @return void
     * @throws Exception
     */
    public function testSetCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $commands = [
            sprintf('%s set %s DB_USER secret.user "DB Configs" --public-key %s --create', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEncFile, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_PASS secret.pass --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEncFile, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_HOST secret.host --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEncFile, $pathAbsolutePublicKey),
            sprintf('%s set %s DB_NAME secret.name --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEncFile, $pathAbsolutePublicKey),
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
     * 7) Test display command with public key (encrypted content).
     *
     * @return void
     * @throws Exception
     */
    public function testDisplayCommand(): void
    {
        /* Arrange */
        $pathAbsoluteEncFile = self::getPathAbsoluteWorking(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = self::getPathAbsoluteKeys(GenerateKeysCommand::NAME_PUBLIC_KEY);
        $command = sprintf('%s display %s --load-encrypted --public-key %s', self::PATH_EXECUTE_PHP_VAULT_PATH, $pathAbsoluteEncFile, $pathAbsolutePublicKey);
        $overheadLines = 5;
        $expectedEntries = 4;

        /* Act */
        $output = $this->executeCommand($command);
        $actualEntries = count(explode(Logger::LB, $output)) - $overheadLines;

        /* Assert */
        $this->assertSame($expectedEntries, $actualEntries);
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
        $files = array_diff(scandir($directory), ['.', '..']);

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
        $pathWriter = $pathWriter === false ? null : $pathWriter;

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
     */
    public static function getPathAbsoluteRootComposerJson(): string
    {
        $base = new BaseCommand('test');
        return $base->getComposerJsonRootPath();
    }

    /**
     * Returns an absolute path of given fs elements.
     *
     * @return string
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
