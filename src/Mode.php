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

class Mode
{
    const MODE_NONE = 0;

    const MODE_ENCRYPT = 1;

    const MODE_DECRYPT = 2;

    private int $mode = self::MODE_NONE;

    /**
     * Mode constructor.
     */
    public function __construct()
    {
    }

    /**
     * Sets the current mode.
     *
     * @param int $mode
     * @throws Exception
     */
    public function set(int $mode)
    {
        if (!in_array($mode, [self::MODE_NONE, self::MODE_ENCRYPT, self::MODE_DECRYPT])) {
            throw new Exception('Unknown mode.');
        }

        $this->mode = $mode;
    }

    /**
     * Gets the current mode.
     *
     * @return int
     */
    public function get(): int
    {
        return $this->mode;
    }
}