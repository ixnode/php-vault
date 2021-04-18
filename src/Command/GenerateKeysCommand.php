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

use Exception;
use Ixnode\PhpVault\PHPVault;
use Ixnode\PhpVault\TypeCheck\TypeCheck;

class GenerateKeysCommand extends BaseCommand
{
    const COMMAND = 'generate-keys';

    const ALIAS = 'gk';

    const DESCRIPTION = 'Generates and displays a private and public key.';

    const PATH_DEFAULT_KEY_FOLDER = '.keys';

    const OPTION_PERSIST = 'persist';

    const OPTION_PERSIST_FOLDER = 'persist-folder';

    /**
     * GenerateKeysCommand constructor.
     */
    public function __construct()
    {
        parent::__construct(self::COMMAND, self::DESCRIPTION);

        $this
            ->option('-p --persist', 'Persists generated keys to given folder.', function($value) { return TypeCheck::isBoolean($value); }, false)
            ->option('-f --persist-folder', 'The path to persists the key pair.', null, self::PATH_DEFAULT_KEY_FOLDER)
            ->usage(
                '<bold>  $0 generate-keys</end> ## Simply shows the key pair.<eol/>'.
                '<bold>  $0 generate-keys</end> <comment>--persist</end> ## Also persists key pair to folder ".keys".<eol/>'.
                '<bold>  $0 generate-keys</end> <comment>--persist --persist-folder .ppk</end> ## Also persists key pair to folder ".ppk".<eol/>'
            );
    }

    /**
     * Bootstrap generated keys function.
     *
     * @return void
     * @throws Exception
     */
    public function execute(): void
    {
        /* Initiate the PhpVault Core */
        $core = new PHPVault(true);

        /* Load options */
        $persist = $this->getOption(self::OPTION_PERSIST);

        /* Display the private and public key */
        if (!$persist) {
            $this->logger->getDisplay()->privateAndPublicKeys($core);
        }

        /* Persist keys */
        $this->persistKeys($core);
    }

    /**
     * Persist keys.
     *
     * @param PHPVault $core
     * @return void
     * @throws Exception
     */
    protected function persistKeys(PHPVault $core): void
    {
        /* Check if persist option exists. */
        if (!$this->getOption(self::OPTION_PERSIST)) {
            return;
        }

        /* Get key folder. */
        $keyFolderAbsolute = sprintf('%s/%s', $this->root, $this->getOption(self::OPTION_PERSIST_FOLDER));

        /* Check if target is a directory. */
        if (file_exists($keyFolderAbsolute)) {
            $this->logger->error('Path "{path}" already exists. If you want to persist the generated keys, delete the existing folder.', array('path' => $keyFolderAbsolute, ), true, true);
            return;
        }

        /* Create key folder. */
        mkdir($keyFolderAbsolute);

        /* Build private key path. */
        $privateKey = 'private.key';
        $privateKeyAbsolute = sprintf('%s/%s', $keyFolderAbsolute, $privateKey);

        /* Build public key path. */
        $publicKey = 'public.key';
        $publicKeyAbsolute = sprintf('%s/%s', $keyFolderAbsolute, $publicKey);

        /* Build .gitignore path. */
        $gitignoreContent = <<<CONTENT
# ignore private key
/$privateKey
CONTENT;
        $gitignore = '.gitignore';
        $gitignoreAbsolute = sprintf('%s/%s', $keyFolderAbsolute, $gitignore);

        /* Write files. */
        file_put_contents($privateKeyAbsolute, $core->getKeyPair()->getPrivateKey());
        file_put_contents($publicKeyAbsolute, $core->getKeyPair()->getPublicKey());
        file_put_contents($gitignoreAbsolute, $gitignoreContent);

        /* Check files. */
        if (!file_exists($privateKeyAbsolute) || !file_exists($publicKeyAbsolute) || !file_exists($gitignoreAbsolute)) {
            $this->logger->error('An error occurred while writing the keys.', array(), true, true);
            return;
        }

        /* Success message. */
        $this->logger->ok('The key pair is written to folder "{path}"', array('path' => $keyFolderAbsolute, ), true, true);
    }
}
