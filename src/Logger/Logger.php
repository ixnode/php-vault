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

namespace Ixnode\PhpVault\Logger;

use Exception;
use Ahc\Cli\Output\Writer;

class Logger
{
    const LOG_LEVEL_INFO = 0;

    const LOG_LEVEL_OK = 1;

    const LOG_LEVEL_WARN = 2;

    const LOG_LEVEL_ERROR = 3;

    const LB = "\n";

    protected Writer $writer;

    protected Display $display;

    /**
     * Logger constructor.
     *
     * @param Writer $writer
     */
    public function __construct(Writer $writer)
    {
        $this->writer = $writer;

        $this->display = new Display($this);
    }

    /**
     * Returns the display class.
     *
     * @return Display
     */
    public function getDisplay(): Display
    {
        return $this->display;
    }

    /**
     * Returns the writer class.
     *
     * @return Writer
     */
    public function getWriter(): Writer
    {
        return $this->writer;
    }

    /**
     * Info logger.
     *
     * @param string $message
     * @param string[]|int[] $context
     * @param bool $eol
     * @param bool $sol
     * @return void
     * @throws Exception
     */
    public function info(string $message, array $context = array(), bool $eol = false, bool $sol = false): void
    {
        $this->log(self::LOG_LEVEL_INFO, $message, $context, $eol, $sol);
    }

    /**
     * Ok logger.
     *
     * @param string $message
     * @param string[]|int[] $context
     * @param bool $eol
     * @param bool $sol
     * @return void
     * @throws Exception
     */
    public function ok(string $message, array $context = array(), bool $eol = false, bool $sol = false): void
    {
        $this->log(self::LOG_LEVEL_OK, $message, $context, $eol, $sol);
    }

    /**
     * Warn logger.
     *
     * @param string $message
     * @param string[]|int[] $context
     * @param bool $eol
     * @param bool $sol
     * @return void
     * @throws Exception
     */
    public function warn(string $message, array $context = array(), bool $eol = false, bool $sol = false): void
    {
        $this->log(self::LOG_LEVEL_WARN, $message, $context, $eol, $sol);
    }

    /**
     * Error logger.
     *
     * @param string $message
     * @param string[]|int[] $context
     * @param bool $eol
     * @param bool $sol
     * @return void
     * @throws Exception
     */
    public function error(string $message, array $context = array(), bool $eol = false, bool $sol = false): void
    {
        $this->log(self::LOG_LEVEL_ERROR, $message, $context, $eol, $sol);
    }

    /**
     * Log wrap function.
     *
     * @param int $level
     * @param string $message
     * @param string[]|int[] $context
     * @param bool $eol
     * @param bool $sol
     * @return void
     * @throws Exception
     */
    protected function log(int $level, string $message, array $context = array(), bool $eol = false, bool $sol = false): void
    {
        /* Interpolates the given $message with the given $context. */
        $message = $this->interpolate($message, $context);

        /* Print line break. */
        if ($sol) {
            print self::LB;
        }

        /* Print log message. */
        switch ($level)
        {
            case self::LOG_LEVEL_OK: $this->writer->ok($message, $eol); break;
            case self::LOG_LEVEL_INFO: $this->writer->info($message, $eol); break;
            case self::LOG_LEVEL_WARN: $this->writer->warn($message, $eol); break;
            case self::LOG_LEVEL_ERROR: $this->writer->error($message, $eol); break;
            default: throw new Exception($this->interpolate('The given log level "{log-level}" is unknown.', array('log-level' => $level)));
        }
    }

    /**
     * Interpolates context values into the message placeholders.
     *
     * @param string $message
     * @param string[]|int[] $context
     * @return string
     */
    protected function interpolate(string $message, array $context = array()): string
    {
        $replace = array();

        /* Builds replace array. */
        foreach ($context as $key => $val) {
            $replace['{' . $key . '}'] = $val;
        }

        /* Replaces all placeholders within $message. */
        return strtr($message, $replace);
    }
}
