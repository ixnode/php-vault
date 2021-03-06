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

namespace Ixnode\PhpVault\Command;

use Ahc\Cli\Application;
use Ahc\Cli\Application as App;
use Ahc\Cli\Helper\OutputHelper;
use Ahc\Cli\Input\Command;
use Ahc\Cli\IO\Interactor;
use Ahc\Cli\Output\Writer;
use Composer\Autoload\ClassLoader;
use Ixnode\PhpVault\Exception\PHPVaultNullException;
use Ixnode\PhpVault\Exception\BasePHPVaultException;
use Ixnode\PhpVault\PHPVault;
use Ixnode\PhpVault\Logger\Logger;
use Exception;
use Ixnode\PhpVault\TypeCheck\TypeCheck;
use Ixnode\PhpVault\Vault\Reader;
use ReflectionClass;
use SodiumException;
use Ixnode\PhpVault\Tools\Converter;
use Throwable;

/**
 * Class BaseCommand
 *
 * @package Ixnode\PhpVault\Command
 *
 * @method BaseCommand displayNoKeyLoaded()
 */
abstract class BaseCommand extends Command
{
    const LOGO = 'PHPVault command line interpreter.';

    const OPTION_PRIVATE_KEY = 'private-key';

    const OPTION_PUBLIC_KEY = 'public-key';

    const TEMPLATE_SIMPLE_EXCEPTION = '<eol/><boldRed>%s</end><red>: %s</end><eol/>';

    protected Writer $writer;

    protected Logger $logger;

    protected ?string $root;

    /**
     * Abstract function handle to handle all the command stuff.
     */
    abstract public function handle(): void;

    /**
     * BaseCommand constructor.
     *
     * @param string $name
     * @param string $desc
     * @param bool $allowUnknown
     * @param App|null $app
     * @throws Exception
     */
    public function __construct(string $name, string $desc = '', bool $allowUnknown = false, App $app = null)
    {
        parent::__construct($name, $desc, $allowUnknown, $app);

        /** @var Interactor|null $io Gets the Interactor  */
        $io = $app instanceof App ? $app->io() : null;

        /* Initiate Writer */
        $this->writer = $io !== null ? $io->writer() : new Writer();

        /* Initiate Logger */
        $this->logger = new Logger($this->writer);

        /* Set root path */
        $this->root = $this->getComposerJsonRootPath();

        /* Add debug option */
        $this->option('-D --debug', 'Set application in debug mode.', function ($value) {
            return TypeCheck::isBoolean($value);
        }, false);
    }

    /**
     * The execute function from Ahc\Cli\Application
     *
     * @return int
     * @throws Exception
     */
    public function execute(): int
    {
        try {
            $this->handle();
        } catch (BasePHPVaultException $exception) {
            if ($this->getOption('debug')) {
                $this->printTrace($exception);
            } else {
                $this->printSimpleException($exception);
            }

            return $exception->getReturnCode();
        }

        return 0;
    }

    /**
     * Prints a simple exception message.
     *
     * @param Throwable $exception
     * @return void
     */
    public function printSimpleException(Throwable $exception): void
    {
        $message = sprintf(
            self::TEMPLATE_SIMPLE_EXCEPTION,
            (new ReflectionClass($exception))->getShortName(),
            $exception->getMessage()
        );

        $this->writer->colors($message);
    }

    /**
     * Print stack trace and error msg of an exception.
     *
     * @param Throwable $exception
     * @return void
     */
    public function printTrace(Throwable $exception): void
    {
        $outputHelper = new OutputHelper($this->io()->writer());
        $outputHelper->printTrace($exception);
    }

    /**
     * Returns an option from command line.
     *
     * @param string $option
     * @param string|bool $default
     * @param bool $replaceWithDefaultIfTrue
     * @return mixed
     * @throws Exception
     */
    protected function getOption(string $option, $default = null, bool $replaceWithDefaultIfTrue = false)
    {
        $option = $this->convertToCamelCase($option);

        $return = $this->registered($option) ? $this->$option : $default;

        if ($replaceWithDefaultIfTrue && $return === true) {
            $return = $default;
        }

        return $return;
    }

    /**
     * Returns an argument from command line.
     *
     * @param string $argument
     * @param null $default
     * @return mixed
     * @throws Exception
     */
    protected function getArgument(string $argument, $default = null)
    {
        $arguments = $this->args();

        $argument = $this->convertToCamelCase($argument);

        return array_key_exists($argument, $arguments) ? $arguments[$argument] : $default;
    }

    /**
     * Converts given string into CamelCase.
     *
     * @param string $value
     * @return string
     * @throws PHPVaultNullException
     */
    protected function convertToCamelCase(string $value): string
    {
        /* Replace capitals to "-capital". */
        $value = Converter::preg_replace_string('~([A-Z])~', '-$1', $value);

        /* Split string by - */
        $array = explode('-', $value);

        /* Convert each string part into "strtolower" and "ucfirst". */
        $array = array_map(function ($element) {
            return ucfirst(strtolower($element));
        }, $array);

        /* Rebuild string. */
        return lcfirst(implode('', $array));
    }

    /**
     * Returns the composer.json root path (project path).
     *
     * @return string
     * @throws Exception
     */
    public function getComposerJsonRootPath(): string
    {
        $reflection = new ReflectionClass(ClassLoader::class);

        if ($reflection->getFileName() === false) {
            throw new Exception('The file name of ClassLoader class was not found.');
        }

        return dirname($reflection->getFileName(), 3);
    }

    /**
     * Returns the default path to private key.
     *
     * @param string $path
     * @param string $name
     * @return string
     * @throws Exception
     */
    protected function getPrivateKeyPath(string $path = '.keys', string $name = 'private.key'): string
    {
        return sprintf('%s/%s/%s', $this->getComposerJsonRootPath(), $path, $name);
    }

    /**
     * Returns the default path to public key.
     *
     * @param string $path
     * @param string $name
     * @return string
     * @throws Exception
     */
    protected function getPublicKeyPath(string $path = '.keys', string $name = 'public.key'): string
    {
        return sprintf('%s/%s/%s', $this->getComposerJsonRootPath(), $path, $name);
    }

    /**
     *
     *
     * @param PHPVault $phpVaultCore
     * @return bool
     * @throws SodiumException
     * @throws Exception
     */
    protected function loadPrivateOrPublicKey(PHPVault $phpVaultCore): bool
    {
        $privateKey = $this->getOption(self::OPTION_PRIVATE_KEY, $this->getPrivateKeyPath(), true);
        $publicKey = $this->getOption(self::OPTION_PUBLIC_KEY, $this->getPublicKeyPath(), true);

        /* Load private key if given. */
        if ($publicKey) {

            /* Check key. */
            if (!file_exists($publicKey)) {
                $this->logger->getDisplay()->fileNotFound($publicKey);
                return false;
            }

            $phpVaultCore->getKeyPair()->loadPublicKeyFromFile($publicKey);
            return true;
        }

        /* Load private key if given. */
        if ($privateKey) {

            /* Check key. */
            if (!file_exists($privateKey)) {
                $this->logger->getDisplay()->fileNotFound($privateKey);
                return false;
            }

            $phpVaultCore->getKeyPair()->loadPrivateKeyFromFile($privateKey);
            return true;
        }

        return true;
    }

    /**
     * Writes all environment variables from vault to file.
     *
     * @param PHPVault $phpVaultCore
     * @param string|null $envFile
     * @param string $outputType
     * @param bool $ignoreExistingFile
     * @return void
     * @throws Exception
     */
    protected function writeEnvVariables(PHPVault $phpVaultCore, ?string $envFile = null, string $outputType = Reader::OUTPUT_TO_ENCRYPTED, bool $ignoreExistingFile = false): void
    {
        /* Check if option was given to write a file. */
        if (!$envFile) {
            return;
        }

        /* Check that the given env file exists. */
        if (!$ignoreExistingFile && file_exists($envFile)) {
            $this->logger->getDisplay()->fileAlreadyExists($envFile);
            return;
        }

        /* Write file */
        $envFileString = $phpVaultCore->getVault()->getWriter()->getEnvString($outputType, true);
        file_put_contents($envFile, $envFileString);

        /* Check that the given env file was written. */
        if (!file_exists($envFile)) {
            $this->logger->getDisplay()->writeFileErrorOccurred($envFile);
            return;
        }

        /* Print success */
        $this->logger->getDisplay()->fileSuccessfullyWritten($envFile);
    }
}
