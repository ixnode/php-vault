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
use Exception;
use Ixnode\PhpVault\PHPVault;
use Ixnode\PhpVault\TypeCheck\TypeCheck;

class DisplayCommand extends BaseCommand
{
    const COMMAND = 'display';

    const ALIAS = 'd';

    const DESCRIPTION = 'Displays the environment variables from given file.';

    const ARGUMENT_ENV_FILE = 'env-file';

    const OPTION_LOAD_ENCRYPTED = 'load-encrypted';

    const OPTION_DISPLAY_DECRYPTED = 'display-decrypted';

    const OPTION_PRIVATE_KEY = 'private-key';

    const OPTION_PUBLIC_KEY = 'public-key';

    const OPTION_WRITE_ENV = 'write-env';

    /**
     * GenerateKeysCommand constructor.
     *
     * @param bool $allowUnknown
     * @param App|null $app
     */
    public function __construct(bool $allowUnknown = false, App $app = null)
    {
        parent::__construct(self::COMMAND, self::DESCRIPTION, $allowUnknown, $app);

        $this
            ->argument('<env-file>', 'The environment file to display.')
            ->option('-e --load-encrypted', 'Indicates that an encrypted file is being loaded. Requires a public or a private key.', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->option('-d --display-decrypted', 'Specifies that the output is to be decrypted. Requires a private key.', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->option('-P --private-key', 'Specifies a private key to be loaded.')
            ->option('-p --public-key', 'Specifies a public key to be loaded.')
            ->option('-w --write-env', 'Specifies that the content of vault is to be saved to a file.')
            ->usage(
                '<bold>  $0 display</end> <comment><env-file></end> ## Loads a given decrypted environment file and displays its contents in encrypted way. Requires a public key.<eol/>'.
                '<bold>  $0 display</end> <comment><env-file> --load-encrypted</end> ## Loads a given encrypted environment file and displays its contents in encrypted way. Requires a public key.<eol/>'.
                '<bold>  $0 display</end> <comment><env-file> --display_decrypted</end> ## Loads a given decrypted environment file and displays its contents in decrypted way. Requires no key.<eol/>'.
                '<bold>  $0 display</end> <comment><env-file> --load-encrypted --display_decrypted</end> ## Loads a given encrypted environment file and displays its contents in decrypted way. Requires a private key.<eol/>'
            );
    }

    /**
     * Bootstrap display function.
     *
     * @return void
     * @throws Exception
     */
    public function execute(): void
    {
        /* Load arguments and options */
        $envFile = $this->getArgument(self::ARGUMENT_ENV_FILE);
        $loadEncrypted = $this->getOption(self::OPTION_LOAD_ENCRYPTED, false);
        $displayDecrypted = $this->getOption(self::OPTION_DISPLAY_DECRYPTED, false);
        $writeEnv = $this->getOption(self::OPTION_WRITE_ENV);

        /* Check that the env file was given. */
        if (!$envFile) {
            $this->logger->getDisplay()->noEnvFileGiven();
            return;
        }

        /* Check that the given env file exists. */
        if (!file_exists($envFile)) {
            $this->logger->getDisplay()->fileNotFound($envFile);
            return;
        }

        /* Initiates the PhpVault Core. Loads private or public key from $_SERVER if given. */
        $core = new PHPVault(false);

        /* Loads private or public key. */
        if (!$this->loadPrivateOrPublicKey($core)) {
            return;
        }

        /* Load env file */
        $core->getVault()->getReader()->addFileToVault($envFile, !$loadEncrypted);

        /* Displays the vault */
        $this->logger->getDisplay()->envVariables($core, $displayDecrypted);

        /* Writes the vault */
        $this->writeEnvVariables($core, $writeEnv, $displayDecrypted);
    }
}
