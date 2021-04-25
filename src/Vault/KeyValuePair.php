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

namespace Ixnode\PhpVault\Vault;

use Ixnode\PhpVault\Decrypter;
use Ixnode\PhpVault\Encrypter;
use SodiumException;

class KeyValuePair
{
    protected string $name;

    protected ?string $valueEncrypted;

    protected ?string $descriptionEncrypted;

    protected ?string $valueDecrypted;

    protected ?string $descriptionDecrypted;

    protected bool $decrypted = false;

    protected bool $encrypted = false;

    /**
     * Item constructor.
     *
     * @param string $name
     * @param string|null $valueEncrypted
     * @param string|null $descriptionEncrypted
     * @param string|null $valueDecrypted
     * @param string|null $descriptionDecrypted
     */
    public function __construct(string $name, string $valueEncrypted = null, string $descriptionEncrypted = null, string $valueDecrypted = null, string $descriptionDecrypted = null)
    {
        $this->name = $name;

        $this->valueEncrypted = $valueEncrypted;
        $this->descriptionEncrypted = $descriptionEncrypted;
        $this->setEncrypted($this->valueEncrypted !== null);

        $this->valueDecrypted = $valueDecrypted;
        $this->descriptionDecrypted = $descriptionDecrypted;
        $this->setDecrypted($this->valueDecrypted !== null);
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /**
     * @return ?string
     */
    public function getValueEncrypted(): ?string
    {
        return $this->valueEncrypted;
    }

    /**
     * @param string|null $valueEncrypted
     * @return void
     */
    public function setValueEncrypted(?string $valueEncrypted): void
    {
        $this->valueEncrypted = $valueEncrypted;
    }

    /**
     * @return string|null
     */
    public function getDescriptionEncrypted(): ?string
    {
        return $this->descriptionEncrypted;
    }

    /**
     * @param string|null $descriptionEncrypted
     * @return void
     */
    public function setDescriptionEncrypted(?string $descriptionEncrypted): void
    {
        $this->descriptionEncrypted = $descriptionEncrypted;
    }

    /**
     * @return string|null
     */
    public function getValueDecrypted(): ?string
    {
        return $this->valueDecrypted;
    }

    /**
     * @param string|null $valueDecrypted
     * @return void
     */
    public function setValueDecrypted(?string $valueDecrypted): void
    {
        $this->valueDecrypted = $valueDecrypted;
    }

    /**
     * @return string|null
     */
    public function getDescriptionDecrypted(): ?string
    {
        return $this->descriptionDecrypted;
    }

    /**
     * @param string|null $descriptionDecrypted
     * @return void
     */
    public function setDescriptionDecrypted(?string $descriptionDecrypted): void
    {
        $this->descriptionDecrypted = $descriptionDecrypted;
    }

    /**
     * Returns the value decrypted or encrypted.
     *
     * @param bool $decrypted
     * @return string|null
     */
    public function getValue(bool $decrypted = false): ?string
    {
        return $decrypted ? $this->getValueDecrypted() : $this->getValueEncrypted();
    }

    /**
     * Returns the description decrypted or encrypted.
     *
     * @param bool $decrypted
     * @return string|null
     */
    public function getDescription(bool $decrypted = false): ?string
    {
        return $decrypted ? $this->getDescriptionDecrypted() : $this->getDescriptionEncrypted();
    }

    /**
     * @return bool
     */
    public function isDecrypted(): bool
    {
        return $this->decrypted;
    }

    /**
     * @param bool $decrypted
     * @return void
     */
    public function setDecrypted(bool $decrypted): void
    {
        $this->decrypted = $decrypted;
    }

    /**
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    /**
     * @param bool $encrypted
     * @return void
     */
    public function setEncrypted(bool $encrypted): void
    {
        $this->encrypted = $encrypted;
    }

    /**
     * Decrypts this class.
     *
     * @param Decrypter $decrypter
     * @param bool $force
     * @return $this
     * @throws SodiumException
     */
    public function decrypt(Decrypter $decrypter, bool $force = false): KeyValuePair
    {
        /* Class is already decrypted */
        if ($this->isDecrypted() && !$force) {
            return $this;
        }

        $this->setValueDecrypted(null);
        $this->setDescriptionDecrypted(null);

        $valueEncrypted = $this->getValueEncrypted();
        if ($valueEncrypted !== null) {
            $this->setValueDecrypted($decrypter->decrypt($valueEncrypted));
        }

        $descriptionEncrypted = $this->getDescriptionEncrypted();
        if ($descriptionEncrypted !== null) {
            $this->setDescriptionDecrypted($decrypter->decrypt($descriptionEncrypted));
        }

        $this->setDecrypted(true);

        return $this;
    }

    /**
     * Encrypts this class.
     *
     * @param Encrypter $encrypter
     * @param bool $force
     * @return $this
     * @throws SodiumException
     */
    public function encrypt(Encrypter $encrypter, bool $force = false): KeyValuePair
    {
        /* Class is already encrypted */
        if ($this->isEncrypted() && !$force) {
            return $this;
        }

        $this->setValueEncrypted(null);
        $this->setDescriptionEncrypted(null);

        if ($this->getValueDecrypted() !== null) {
            $this->setValueEncrypted($encrypter->encrypt($this->getValueDecrypted()));
        }

        if ($this->getDescriptionDecrypted() !== null) {
            $this->setDescriptionEncrypted($encrypter->encrypt($this->getDescriptionDecrypted()));
        }

        $this->setEncrypted(true);

        return $this;
    }
}
