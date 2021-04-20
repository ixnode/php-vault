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

    const PATH_TEST_FOLDER = '.test-folder';

    const PATH_ENV_ENC = '.env.enc';

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
        $pathAbsoluteTestFolder = self::getPathTestAbsolute();

        /* Act */
        /* Nothing to do. */

        /* Assert */
        $this->assertTrue(!file_exists($pathAbsoluteTestFolder));
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
        $command = sprintf('%s gk --persist %s', self::PATH_EXECUTE_PHP_VAULT_PATH, self::PATH_TEST_FOLDER);
        $pathAbsoluteTestFolder = self::getPathTestAbsolute();
        $search = 'The key pair is written to folder';

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
        $this->assertTrue(file_exists($pathAbsoluteTestFolder));
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
        $pathAbsolutePublicKey = $this->getPathTestAbsolute(GenerateKeysCommand::NAME_PUBLIC_KEY);
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
        $pathAbsoluteEncFile = $this->getPathTestAbsolute(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = $this->getPathTestAbsolute(GenerateKeysCommand::NAME_PUBLIC_KEY);
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
        $pathAbsoluteEncFile = $this->getPathTestAbsolute(self::PATH_ENV_ENC);
        $pathAbsolutePublicKey = $this->getPathTestAbsolute(GenerateKeysCommand::NAME_PUBLIC_KEY);
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
     * - Delete created files and folders.
     *
     * @return void
     * @throws Exception
     */
    public static function tearDownAfterClass(): void
    {
        /* Get absolute path to ppk folder */
        $pathAbsoluteTestFolder = self::getPathTestAbsolute();

        /* Delete files  */
        $findFiles = glob(sprintf('%s/*.*', $pathAbsoluteTestFolder));
        if ($findFiles !== false) {
            array_map('unlink', $findFiles);
        }

        /* Delete dot files  */
        $findDotFiles = glob(sprintf('%s/.git*', $pathAbsoluteTestFolder));
        if ($findDotFiles !== false) {
            array_map('unlink', $findDotFiles);
        }
        $findDotFiles = glob(sprintf('%s/.env*', $pathAbsoluteTestFolder));
        if ($findDotFiles !== false) {
            array_map('unlink', $findDotFiles);
        }

        /* Delete folder */
        rmdir($pathAbsoluteTestFolder);

        /* An error occurred while trying to delete the ppk folder */
        if (file_exists($pathAbsoluteTestFolder)) {
            throw new Exception(sprintf('Unable to delete folder "%s"', $pathAbsoluteTestFolder));
        }
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
        /* Builds path to new writer */
        $pathWriter = tempnam(sys_get_temp_dir(), self::TEMP_PREFIX);
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
    public static function getComposerJsonRootPath(): string
    {
        $base = new BaseCommand('test');
        return $base->getComposerJsonRootPath();
    }

    /**
     * Returns the ppk folder of this project.
     *
     * @param string $relativePath
     * @return string
     */
    public static function getPathAbsolute(string $relativePath): string
    {
        return sprintf('%s/%s', self::getComposerJsonRootPath(), $relativePath);
    }

    /**
     * Returns the ppk folder of this project.
     *
     * @param string|null $relativePath
     * @return string
     */
    public static function getPathTestAbsolute(string $relativePath = null): string
    {
        if ($relativePath !== null) {
            return sprintf('%s/%s/%s', self::getComposerJsonRootPath(), self::PATH_TEST_FOLDER, $relativePath);
        } else {
            return sprintf('%s/%s', self::getComposerJsonRootPath(), self::PATH_TEST_FOLDER);
        }
    }
}
