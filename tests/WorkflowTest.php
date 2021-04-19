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

final class WorkflowTest extends TestCase
{
    const TEMP_PREFIX = 'php-vault';

    /**
     * Check help.
     *
     * @throws Exception
     */
    public function testHelp(): void
    {
        /* Arrange */
        $command = 'bin/php-vault --help';
        $search = sprintf('version %s', PHPVault::VERSION);

        /* Act */
        $output = $this->executeCommand($command);

        /* Assert */
        $this->assertIsInt(strpos($output, $search));
    }

    /**
     * @param string $command
     * @return string
     * @throws Exception
     */
    protected function executeCommand(string $command): string
    {
        $writer = tempnam(sys_get_temp_dir(), self::TEMP_PREFIX);

        $writer = $writer === false ? null : $writer;

        $interactor = new Interactor(null, $writer);

        $cli = new Cli($command, $interactor, function ($exitCode = 0) { });
        $cli->handle();

        $output = file_get_contents($writer);

        return $output === false ? '' : $output;
    }
}
