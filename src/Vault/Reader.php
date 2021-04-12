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

class Reader
{
    protected Vault $vault;

    const PATTERN_NAME_VALUE = '~^([a-z][a-z0-9]+)=(.+)$~i';

    const PATTERN_DESCRIPTION = '~^# (.+)$~i';

    /**
     * Writer constructor.
     *
     * @param Vault $vault
     */
    public function __construct(Vault $vault)
    {
        $this->vault = $vault;
    }

    /**
     * Converts given stream to array.
     *
     * @param string $stream
     * @return array[]
     */
    public function convertStreamToArray(string $stream): array
    {
        $lines = explode("\n", $stream);
        $return = array();

        $default = array(
            'name' => null,
            'value' => null,
            'description' => null,
        );

        $current = $default;
        foreach ($lines as $line) {
            $matches = array();

            /* # DESCRIPTION detected */
            if (preg_match(self::PATTERN_DESCRIPTION, $line, $matches)) {

                /* add parsed values to current array */
                $current['description'] = $matches[1];

                /* go to next line */
                continue;
            }

            /* NAME=VALUE detected */
            if (preg_match(self::PATTERN_NAME_VALUE, $line, $matches)) {

                /* add parsed values to current array */
                $current['name'] = $matches[1];
                $current['value'] = $matches[2];

                /* add current array to return array */
                $return[$current['name']] = array(
                    'value' => $current['value'],
                    'description' => $current['description'],
                );

                /* create new current array */
                $current = $default;

                /* go to next line */
                continue;
            }
        }

        return $return;
    }
}
