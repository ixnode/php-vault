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

class GenerateKeysCommand extends BaseCommand
{
    const COMMAND = 'generate-keys';

    const ALIAS = 'gk';

    const DESCRIPTION = 'Generates and displays a private and public key.';

    const PATH_DEFAULT_KEY_FOLDER = '.keys';

    const NAME_PRIVATE_KEY = 'private.key';

    const NAME_PUBLIC_KEY = 'public.key';

    const OPTION_PERSIST = 'persist';

    const OPTION_PERSIST_FOLDER = 'persist-folder';

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
            ->option('-p --persist', 'Persists generated keys to given folder', null, false)
            ->option('-1 --version1', 'Generate version 1 keys', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->option('-2 --version2', 'Generate version 2 keys', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->usage(
                '<bold>  $0 generate-keys</end> ## Simply shows the key pair.<eol/>'.
                '<bold>  $0 generate-keys</end> <comment>--persist</end> ## Also persists key pair to folder ".keys" (Default path).<eol/>'.
                '<bold>  $0 generate-keys</end> <comment>--persist .ppk</end> ## Also persists key pair to folder ".ppk".<eol/>'
            );
    }

    /**
     * Bootstrap generated keys function.
     *
     * @return void
     * @throws Exception
     */
    public function handle(): void
    {
        /* Initiate the PhpVault Core */
        $phpVaultCore = new PHPVault(true);

        /* Load options */
        $persist = $this->getOption(self::OPTION_PERSIST);

        /* Display the private and public key */
        if (!$persist) {
            $this->logger->getDisplay()->privateAndPublicKeys($phpVaultCore, $this->getVersion());
        }

        /* Persist keys */
        $this->persistKeys($phpVaultCore);
    }

    /**
     * Returns the wanted version of keys.
     *
     * @return string
     * @throws Exception
     */
    protected function getVersion(): string
    {
        $version1 = $this->getOption('version1', false);
        $version2 = $this->getOption('version2', false);

        switch (true) {
            case $version1:
                return 'v1';

            default:
                return 'v2';
        }
    }

    /**
     * Persist keys.
     *
     * @param PHPVault $phpVaultCore
     * @return void
     * @throws Exception
     */
    protected function persistKeys(PHPVault $phpVaultCore): void
    {
        /* Check if persist option exists. */
        if (!$this->getOption(self::OPTION_PERSIST)) {
            return;
        }

        /* Get key folder. */
        $pathKeys = $this->getOption(self::OPTION_PERSIST, self::PATH_DEFAULT_KEY_FOLDER, true);

        /* Check if target is a directory. */
        if (file_exists($pathKeys)) {
            $this->logger->error('Path "{path}" already exists. If you want to persist the generated keys, delete the existing folder.', array('path' => $pathKeys, ), true, true);
            return;
        }

        /* Create key folder. */
        mkdir($pathKeys);

        /* Build private key path. */
        $privateKey = self::NAME_PRIVATE_KEY;
        $pathPrivateKey = sprintf('%s/%s', $pathKeys, $privateKey);

        /* Build public key path. */
        $publicKey = self::NAME_PUBLIC_KEY;
        $pathPublicKey = sprintf('%s/%s', $pathKeys, $publicKey);

        /* Build .gitignore path. */
        $gitignoreContent = <<<CONTENT
# ignore private key
/$privateKey
CONTENT;
        $gitignore = '.gitignore';
        $gitignoreAbsolute = sprintf('%s/%s', $pathKeys, $gitignore);

        /* Write files. */
        file_put_contents($pathPrivateKey, $phpVaultCore->getKeyPair()->getPrivateKeyCombined());
        file_put_contents($pathPublicKey, $phpVaultCore->getKeyPair()->getPublicKeyCombined());
        file_put_contents($gitignoreAbsolute, $gitignoreContent);

        /* Check files. */
        if (!file_exists($pathPrivateKey) || !file_exists($pathPublicKey) || !file_exists($gitignoreAbsolute)) {
            $this->logger->error('An error occurred while writing the keys.', array(), true, true);
            return;
        }

        /* Success message. */
        $this->logger->ok('The key pair is written to folder "{path}"', array('path' => $pathKeys, ), true, true);

        /* Warn message. */
        $this->logger->warn('Never add the private key to the repository!', [], true, true);
    }
}
