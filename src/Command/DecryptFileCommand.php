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

class DecryptFileCommand extends BaseCommand
{
    const COMMAND = 'decrypt-file';

    const ALIAS = 'df';

    const DESCRIPTION = 'Decrypts a given file. Requires a private key.';

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
            ->argument('<env-file>', 'Specifies the file to be decrypted.')
            ->option('-P --private-key', 'Specifies a private key to be loaded.')
            ->option('-p --public-key', 'Specifies a public key to be loaded.')
            ->usage(
                '<bold>  $0 decrypt-file</end> <comment><env-file></end> ## Decrypts a given file. Requires a <underline>private key</end>.<eol/>'
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
        $envFileEncrypted = $this->getArgument(self::ARGUMENT_ENV_FILE);

        /* Check the name of given file. */
        if (!preg_match('~\.enc$~', $envFileEncrypted)) {
            $this->logger->getDisplay()->fileEncryptedWrongFormat($envFileEncrypted);
            return;
        }

        /* Generates decrypted file name */
        $envFileDecrypted = preg_replace('~\.enc$~', '', $envFileEncrypted);

        /* Set options */
        $displayDecrypted = true;

        /* Check that the given env file exists. */
        if (!file_exists($envFileEncrypted)) {
            $this->logger->getDisplay()->fileNotFound($envFileEncrypted);
            return;
        }

        /* Initiate the PhpVault Core */
        $phpVaultCore = new PHPVault();

        /* Loads private or public key. */
        if (!$this->loadPrivateOrPublicKey($phpVaultCore)) {
            return;
        }

        /* Load env decrypted file */
        $phpVaultCore->getVault()->getReader()->addFileToVault($envFileEncrypted, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_DECRYPTED);

        /* Writes the vault */
        $this->writeEnvVariables($phpVaultCore, $envFileDecrypted, Reader::OUTPUT_TO_DECRYPTED);
    }
}
