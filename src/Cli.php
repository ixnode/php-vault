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

namespace Ixnode\PhpVault;

use Ahc\Cli\Application;
use Ahc\Cli\IO\Interactor;
use Ixnode\PhpVault\Command\BaseCommand;
use Ixnode\PhpVault\Command\GenerateKeysCommand;
use Ixnode\PhpVault\Command\DisplayEnvCommand;
use Ixnode\PhpVault\Command\DisplayCommand;
use Ixnode\PhpVault\Command\SetCommand;
use Ixnode\PhpVault\Command\EncryptFileCommand;
use Ixnode\PhpVault\Command\DecryptFileCommand;
use Ixnode\PhpVault\Command\InfoCommand;
use Exception;

class Cli
{
    /** @var string[] $argv */
    protected array $argv = array();

    /** @var bool $argvLoaded */
    protected bool $argvLoaded = false;

    /** @var Interactor|null $interactor */
    protected ?Interactor $interactor = null;

    /** @var callable The callable to perform exit */
    protected $onExit;

    /**
     * Cli constructor.
     *
     * @param string|null $command
     * @throws Exception
     */
    public function __construct(string $command = null, Interactor $interactor = null, callable $onExit = null)
    {
        // @codeCoverageIgnoreStart
        $this->onExit = $onExit ?? function ($exitCode = 0) {
            exit($exitCode);
        };
        // @codeCoverageIgnoreEnd

        if ($interactor !== null) {
            $this->interactor = $interactor;
        }

        /* Parse given command */
        if (!$this->argvLoaded && $command) {
            $this->setArgv($this->parseCommand($command));
        }

        /* Use cli arguments */
        if (!$this->argvLoaded && array_key_exists('argv', $_SERVER)) {
            $this->setArgv($_SERVER['argv']);
        }

        /* No arguments given */
        if (!$this->argvLoaded) {
            throw new Exception();
        }
    }

    /**
     * Parse given command and split into arguments with the help of bash.
     *
     * @param string $command
     * @return string[]
     */
    public function parseCommandWithBash(string $command): array
    {
        $parsed = array();

        /* Simulate bash argument parser */
        exec(sprintf('for i in %s; do echo $i; done', $command), $parsed);

        return $parsed;
    }

    /**
     * Parse given command and split into arguments with the help of str_getcsv.
     *
     * @param string $command
     * @return string[]
     */
    public function parseCommand(string $command): array
    {
        $parsed = str_getcsv($command, ' ');

        return array_values(
            array_filter($parsed, function ($value) { return ($value !== null && $value !== false && $value !== ""); })
        );
    }

    /**
     * Set argument list.
     *
     * @param string[] $argv
     * @return void
     */
    protected function setArgv(array $argv): void
    {
        $this->argv = $argv;

        $this->argvLoaded = true;
    }

    /**
     * Get parsed argument list.
     *
     * @return string[]
     */
    public function getArgv(): array
    {
        return $this->argv;
    }

    /**
     * Handle cli commands.
     *
     * @return void
     * @throws Exception
     */
    public function handle(): void
    {
        /* Init App with name and version */
        $app = new Application(PHPVault::NAME, PHPVault::VERSION, $this->onExit);

        if ($this->interactor !== null) {
            $app->io($this->interactor);
        }

        /* Add commands with optional aliases */
        $app->add(new GenerateKeysCommand(false, $app), GenerateKeysCommand::ALIAS);
        $app->add(new DisplayEnvCommand(false, $app), DisplayEnvCommand::ALIAS);
        $app->add(new DisplayCommand(false, $app), DisplayCommand::ALIAS);
        $app->add(new SetCommand(false, $app), SetCommand::ALIAS);
        $app->add(new EncryptFileCommand(false, $app), EncryptFileCommand::ALIAS);
        $app->add(new DecryptFileCommand(false, $app), DecryptFileCommand::ALIAS);
        $app->add(new InfoCommand(false, $app), InfoCommand::ALIAS);

        /* Set logo */
        $app->logo(BaseCommand::LOGO);

        /* Handle arguments */
        $app->handle($this->getArgv());
    }
}
