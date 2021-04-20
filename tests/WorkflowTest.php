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
use Ixnode\PhpVault\PHPVault;
use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\Cli;
use Ixnode\PhpVault\Command\BaseCommand;

final class WorkflowTest extends TestCase
{
    const TEMP_PREFIX = 'php-vault';

    const PATH_KEY_FOLDER = '.ppk-test-folder';

    const PATH_EXECUTE_PHP_VAULT_PATH = 'bin/php-vault';

    /**
     * 1) Check help.
     *
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
     * @throws Exception
     */
    public function testEmptyKeyFolder(): void
    {
        /* Arrange */
        $pathAbsolutePpk = self::getPathAbsolutePpk();

        /* Act */
        /* Nothing to do. */

        /* Assert */
        $this->assertTrue(!file_exists($pathAbsolutePpk));
    }

    /**
     * 4) Generates a private public key pair.
     *
     * @throws Exception
     */
    public function testGenerateKeys(): void
    {
        /* Arrange */
        $command = sprintf('%s gk --persist %s', self::PATH_EXECUTE_PHP_VAULT_PATH, self::PATH_KEY_FOLDER);
        $pathAbsolutePpk = self::getPathAbsolutePpk();
        $search = 'The key pair is written to folder';

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
        $this->assertTrue(file_exists($pathAbsolutePpk));
    }


    /**
     * Tidy up.
     *
     * - Delete created files and folders.
     *
     * @throws Exception
     */
    public static function tearDownAfterClass(): void
    {
        /* Get absolute path to ppk folder */
        $pathAbsolutePpk = self::getPathAbsolutePpk();

        /* Delete files  */
        $findFiles = glob(sprintf('%s/*.*', $pathAbsolutePpk));
        if ($findFiles !== false) {
            array_map('unlink', $findFiles);
        }

        /* Delete dot files  */
        $findDotFiles = glob(sprintf('%s/.git*', $pathAbsolutePpk));
        if ($findDotFiles !== false) {
            array_map('unlink', $findDotFiles);
        }

        /* Delete folder */
        rmdir($pathAbsolutePpk);

        /* An error occurred while trying to delete the ppk folder */
        if (file_exists($pathAbsolutePpk)) {
            throw new Exception(sprintf('Unable to delete folder "%s"', $pathAbsolutePpk));
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
    public static function getPathAbsolutePpk(): string
    {
        $base = new BaseCommand('test');
        return sprintf('%s/%s', $base->getComposerJsonRootPath(), self::PATH_KEY_FOLDER);
    }
}
