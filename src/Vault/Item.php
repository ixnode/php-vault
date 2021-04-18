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

class Item
{
    protected string $value;

    protected ?string $description;

    protected ?string $valueDecrypted;

    protected ?string $descriptionDecrypted;

    /**
     * Item constructor.
     *
     * @param string $value
     * @param string|null $description
     * @param string|null $valueDecrypted
     * @param string|null $descriptionDecrypted
     */
    public function __construct(string $value, string $description = null, string $valueDecrypted = null, string $descriptionDecrypted = null)
    {
        $this->value = $value;
        $this->description = $description;
        $this->valueDecrypted = $valueDecrypted;
        $this->descriptionDecrypted = $descriptionDecrypted;
    }

    /**
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * @param string $value
     * @return void
     */
    public function setValue(string $value): void
    {
        $this->value = $value;
    }

    /**
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @param string $description
     * @return void
     */
    public function setDescription(string $description): void
    {
        $this->description = $description;
    }

    /**
     * @return string|null
     */
    public function getValueDecrypted(): ?string
    {
        return $this->valueDecrypted;
    }

    /**
     * @param string $valueDecrypted
     * @return void
     */
    public function setValueDecrypted(string $valueDecrypted): void
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
     * @param string $descriptionDecrypted
     * @return void
     */
    public function setDescriptionDecrypted(string $descriptionDecrypted): void
    {
        $this->descriptionDecrypted = $descriptionDecrypted;
    }
}
