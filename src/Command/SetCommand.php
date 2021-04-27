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

use Ahc\Cli\Application as App;
use Ixnode\PhpVault\PHPVault;
use Exception;
use Ixnode\PhpVault\TypeCheck\TypeCheck;
use Ixnode\PhpVault\Vault\Reader;

class SetCommand extends BaseCommand
{
    const COMMAND = 'set';

    const ALIAS = 's';

    const DESCRIPTION = 'Sets or updates a new variable. Needs a public key.';

    const ARGUMENT_ENV_FILE = 'env-file';

    const ARGUMENT_NAME = 'name';

    const ARGUMENT_VALUE = 'value';

    const ARGUMENT_DESCRIPTION = 'description';

    const OPTION_CREATE = 'create';

    /**
     * GenerateKeysCommand constructor.
     *
     * @param bool $allowUnknown
     * @param App|null $app
     * @throws Exception
     */
    public function __construct(bool $allowUnknown = false, App $app = null)
    {
        parent::__construct(self::COMMAND, self::DESCRIPTION, $allowUnknown, $app);

        $this
            ->argument('<env-file>', 'The environment file to be read (source env file).')
            ->argument('<name>', 'The name of the new variable.')
            ->argument('<value>', 'The value of the new variable.')
            ->argument('[description]', 'The description of the new variable.')
            ->option('-c --create', 'Specifies whether the environment variable is to be created.', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->option('-P --private-key', 'Specifies a private key to be loaded.')
            ->option('-p --public-key', 'Specifies a public key to be loaded.')
            ->usage(
                '<bold>  $0 set</end> <comment><env-file> <name> <value> [description]</end> ## Sets or updates a new variable. Needs a public key.<eol/>'
            );
    }

    /**
     * Bootstrap display environment function.
     *
     * @return void
     * @throws Exception
     */
    public function handle(): void
    {
        /* Reads the arguments */
        $envFile = $this->getArgument(self::ARGUMENT_ENV_FILE);
        $name = $this->getArgument(self::ARGUMENT_NAME);
        $value = $this->getArgument(self::ARGUMENT_VALUE);
        $description = $this->getArgument(self::ARGUMENT_DESCRIPTION);

        /* Reads options */
        $create = $this->getOption(self::OPTION_CREATE, false);

        /* Set options */
        $displayDecrypted = false;

        /* Check that the given env file exists. */
        if (!$create && !file_exists($envFile)) {
            $this->logger->getDisplay()->fileNotFound($envFile);
            return;
        }

        /* Initiates the PhpVault Core. Loads private or public key from $_SERVER if given. */
        $phpVaultCore = new PHPVault();

        /* Loads private or public key. */
        if (!$this->loadPrivateOrPublicKey($phpVaultCore)) {
            return;
        }

        /* Load env file */
        if (file_exists($envFile)) {
            $phpVaultCore->getVault()->getReader()->addFileToVault($envFile, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_ENCRYPTED);
        }

        /* set new name value set */
        $phpVaultCore->getVault()->add($name, $value, $description);

        /* Displays the vault */
        $this->logger->getDisplay()->envVariables($phpVaultCore);

        /* Writes the vault */
        $this->writeEnvVariables($phpVaultCore, $envFile, Reader::OUTPUT_TO_ENCRYPTED, true);
    }
}
