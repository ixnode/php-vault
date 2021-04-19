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

namespace Test\Ixnode\PhpVault;

use Exception;
use Ixnode\PhpVault\Cli;
use PHPUnit\Framework\TestCase;

final class CliTest extends TestCase
{
    /**
     * Test cli parser.
     *
     * @param string $command
     * @param string[] $argv
     * @throws Exception
     * @dataProvider dataProvider
     */
    public function testCliParser(string $command, array $argv): void
    {
        /* Arrange */
        $expected = $argv;

        /* Act */
        $cli = new Cli();
        $actual = $cli->parseCommand($command);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Test cli parser with the help of bash.
     *
     * @param string $command
     * @param string[] $argv
     * @throws Exception
     * @dataProvider dataProviderBash
     */
    public function testCliParserWithBash(string $command, array $argv): void
    {
        /* Arrange */
        $expected = $argv;

        /* Act */
        $cli = new Cli();
        $actual = $cli->parseCommandWithBash($command);

        /* Assert */
        $this->assertSame($expected, $actual);
    }

    /**
     * Define a data Provider.
     *
     * @return string[][]|array[][]
     */
    public function dataProvider(): array
    {
        return [
            /* Empty command */
            ['', []],

            /* Multiple commands */
            ['abc', ['abc']],
            ['abc abc', ['abc', 'abc']],
            ['abc abc abc', ['abc', 'abc', 'abc']],

            /* Quoted commands */
            ['"abc"', ['abc']],

            /* Real commands */
            [
                'bin/php-vault',
                [
                    'bin/php-vault'
                ]
            ],
            [
                'bin/php-vault set .env.enc DB_USER secret.user "DB Configurations Quoted" --public-key --create',
                [
                    'bin/php-vault',
                    'set',
                    '.env.enc',
                    'DB_USER',
                    'secret.user',
                    'DB Configurations Quoted',
                    '--public-key',
                    '--create',
                ]
            ],
            [
                'bin/php-vault set .env.enc DB_USER secret.user "DB Configurations Quoted"    --public-key --create',
                [
                    'bin/php-vault',
                    'set',
                    '.env.enc',
                    'DB_USER',
                    'secret.user',
                    'DB Configurations Quoted',
                    '--public-key',
                    '--create',
                ]
            ],
        ];
    }

    /**
     * Define a data Provider.
     *
     * @return string[][]|array[][]
     */
    public function dataProviderBash(): array
    {
        return [
            /* Empty command */
            ['', []],

            /* Multiple commands */
            ['abc', ['abc']],
            ['abc abc', ['abc', 'abc']],
            ['abc abc abc', ['abc', 'abc', 'abc']],

            /* Quoted commands */
            ['"abc"', ['abc']],
            ['\'abc\'', ['abc']],

            /* Mixed commands */
            ['"abc""def" abc', ['abcdef', 'abc']],
            ['"abc\'abc" abc', ['abc\'abc', 'abc']],
            ['  abc  abc  ', ['abc', 'abc']],
            ['abc"abc"abc abc', ['abcabcabc', 'abc']],
            ['\'abc"abc"abc abc\'', ['abc"abc"abc abc']],

            /* Real commands */
            [
                'bin/php-vault',
                [
                    'bin/php-vault'
                ]
            ],
            [
                'bin/php-vault set .env.enc DB_USER secret.user "DB Configurations Quoted" --public-key --create',
                [
                    'bin/php-vault',
                    'set',
                    '.env.enc',
                    'DB_USER',
                    'secret.user',
                    'DB Configurations Quoted',
                    '--public-key',
                    '--create',
                ]
            ],
            [
                'bin/php-vault set .env.enc DB_USER secret.user \'DB Configurations Quoted\' --public-key --create',
                [
                    'bin/php-vault',
                    'set',
                    '.env.enc',
                    'DB_USER',
                    'secret.user',
                    'DB Configurations Quoted',
                    '--public-key',
                    '--create',
                ]
            ],
            [
                'bin/php-vault set .env.enc DB_USER secret.user "DB Configurations Quoted"    --public-key --create',
                [
                    'bin/php-vault',
                    'set',
                    '.env.enc',
                    'DB_USER',
                    'secret.user',
                    'DB Configurations Quoted',
                    '--public-key',
                    '--create',
                ]
            ],
        ];
    }
}
