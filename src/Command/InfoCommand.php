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

class InfoCommand extends BaseCommand
{
    const COMMAND = 'info';

    const ALIAS = 'i';

    const DESCRIPTION = 'Shows information.';

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
            ->option('-P --private-key', 'Specifies a private key to be loaded.')
            ->option('-p --public-key', 'Specifies a public key to be loaded.')
            ->usage(
                '<bold>  $0 info</end> ## Shows information.<eol/>'
            );
    }

    /**
     * Bootstrap show information function.
     *
     * @return void
     * @throws Exception
     */
    public function execute(): void
    {
        /* Initiate the PhpVault Core */
        $core = new PHPVault();

        /* Loads private or public key. */
        if (!$this->loadPrivateOrPublicKey($core)) {
            return;
        }

        /* No key was loaded */
        if ($core->getKeyPair()->noKeyIsLoaded()) {
            $this->logger->getDisplay()->noKeyLoaded();
            return;
        }

        /* Private key was loaded */
        if ($core->getKeyPair()->getPrivateKey()) {
            $this->logger->getDisplay()->privateKeyLoaded($core);
            $this->logger->getDisplay()->keyLoadedFrom($core->getKeyPair());
            return;
        }

        /* Private key was loaded */
        if ($core->getKeyPair()->getPublicKey()) {
            $this->logger->getDisplay()->publicKeyLoaded($core);
            $this->logger->getDisplay()->keyLoadedFrom($core->getKeyPair());
            return;
        }
    }
}
