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

namespace Ixnode\PhpVault\Exception;

use Exception;

abstract class BasePHPVaultException extends Exception
{
    /* General codes */
    const RETURN_CODE_CORRUPTED_DATA = 100;
    const RETURN_CODE_NULL = 101;
    const RETURN_CODE_VERIFICATION_FAILED = 102;

    /* Public and private key codes */
    const RETURN_CODE_NO_PRIVATE_KEY_LOADED = 150;
    const RETURN_CODE_NO_PUBLIC_KEY_LOADED = 151;
    const RETURN_CODE_PRIVATE_KEY_LOADED = 152;
    const RETURN_CODE_PUBLIC_KEY_LOADED = 153;

    /**
     * Returns the return code of current exception.
     *
     * @return int
     */
    abstract public function getReturnCode(): int;
}

