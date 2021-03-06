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

use Exception;
use Ixnode\PhpVault\Vault\Reader;
use Ixnode\PhpVault\Vault\Vault;
use SodiumException;

class PHPVault
{
    const NAME = 'PHPVault';

    const VERSION = 'v1.0.7';

    const CORE_PUBLIC_KEY = 'zodfptod/VHjzzgdPgT2vk7RThdowsYXLiPP+eNI6D4=';

    const CORE_PRIVATE_KEY = 'WaRZMJ3wkOh4ptENQifAEylJvtVoJ0pAEYFkzsnGR5I=';

    protected Mode $mode;

    protected Encrypter $encrypter;

    protected Decrypter $decrypter;

    protected KeyPair $keyPair;

    protected Vault $vault;

    /**
     * Core constructor.
     *
     * @param bool $forceCreateNewKeys
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @throws SodiumException
     */
    public function __construct(bool $forceCreateNewKeys = false, string $privateKey = null, string $publicKey = null)
    {
        $this->mode = new Mode();
        $this->encrypter = new Encrypter($this);
        $this->decrypter = new Decrypter($this);
        $this->keyPair = new KeyPair($this, $forceCreateNewKeys, $privateKey, $publicKey);
        $this->vault = new Vault($this);
    }

    /**
     * Gets the Mode class.
     *
     * @param int $mode
     * @return void
     * @throws Exception
     */
    public function setMode(int $mode): void
    {
        $this->mode->set($mode);
    }

    /**
     * Gets the Mode class.
     *
     * @return int
     */
    public function getMode(): int
    {
        return $this->mode->get();
    }

    /**
     * Returns the Encrypter class.
     *
     * @return Encrypter
     * @throws Exception
     */
    public function getEncrypter(): Encrypter
    {
        return $this->encrypter;
    }

    /**
     * Returns the Decrypter class.
     *
     * @return Decrypter
     * @throws Exception
     */
    public function getDecrypter(): Decrypter
    {
        return $this->decrypter;
    }

    /**
     * Returns the KeyPair class.
     *
     * @return KeyPair
     */
    public function getKeyPair(): KeyPair
    {
        return $this->keyPair;
    }

    /**
     * Returns the Vault class.
     *
     * @return Vault
     */
    public function getVault(): Vault
    {
        return $this->vault;
    }

    /**
     * Clears the vault.
     *
     * @return void
     */
    public function clearVault(): void
    {
        $this->vault->clear();
    }

    /**
     * Loads private key from file.
     *
     * @param string $privateKey
     * @return void
     * @throws SodiumException
     */
    public function loadPrivateKeyFromFile(string $privateKey): void
    {
        $this->getKeyPair()->loadPrivateKeyFromFile($privateKey);
    }

    /**
     * Loads public key from file.
     *
     * @param string $publicKey
     * @return void
     * @throws SodiumException
     */
    public function loadPublicKeyFromFile(string $publicKey): void
    {
        $this->getKeyPair()->loadPublicKeyFromFile($publicKey);
    }

    /**
     * Imports and adds given env file to vault and $_SERVER.
     *
     * @param string $file
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function importEncryptedEnvFile(string $file): void
    {
        $this->getVault()->getReader()->addFileToVault($file, Reader::LOAD_FROM_ENCRYPTED, Reader::OUTPUT_TO_DECRYPTED);
        $this->getVault()->getWriter()->saveToServer();
        $this->getVault()->getWriter()->saveToEnv();
        $this->getVault()->getWriter()->putEnv();
    }
}
