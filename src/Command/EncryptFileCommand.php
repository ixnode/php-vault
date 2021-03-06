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
use Ixnode\PhpVault\Vault\Reader;

class EncryptFileCommand extends BaseCommand
{
    const COMMAND = 'encrypt-file';

    const ALIAS = 'ef';

    const DESCRIPTION = 'Encrypts a given file. Requires a public key.';

    const ARGUMENT_ENV_FILE = 'env-file';

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
            ->argument('<env-file>', 'Specifies the file to be encrypted.')
            ->option('-P --private-key', 'Specifies a private key to be loaded.')
            ->option('-p --public-key', 'Specifies a public key to be loaded.')
            ->usage(
                '<bold>  $0 encrypt-file</end> <comment><env-file></end> ## Encrypts a given file. Requires a <underline>public key</end>.<eol/>'
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
        $envFileDecrypted = $this->getArgument(self::ARGUMENT_ENV_FILE);
        $envFileEncrypted = sprintf('%s.enc', $envFileDecrypted);

        /* Check if already encrypted */
        if (preg_match('~.+\.enc$~', $envFileDecrypted)) {
            $this->logger->getDisplay()->fileAlreadyEncrypted($envFileDecrypted);
            return;
        }

        /* Check that the given env file exists. */
        if (!file_exists($envFileDecrypted)) {
            $this->logger->getDisplay()->fileNotFound($envFileDecrypted);
            return;
        }

        /* Initiate the PhpVault Core */
        $phpVaultCore = new PHPVault();

        /* Loads private or public key. */
        if (!$this->loadPrivateOrPublicKey($phpVaultCore)) {
            return;
        }

        /* Load env decrypted file */
        $phpVaultCore->getVault()->getReader()->addFileToVault($envFileDecrypted, Reader::LOAD_FROM_DECRYPTED, Reader::OUTPUT_TO_ENCRYPTED);

        /* Writes the vault */
        $this->writeEnvVariables($phpVaultCore, $envFileEncrypted);
    }
}
