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

use PHPUnit\Framework\TestCase;
use Ixnode\PhpVault\Core;
use Exception;
use SodiumException;

final class CoreTest extends TestCase
{
    /**
     * Test decryption.
     *
     * @param string $expected
     * @param string $encrypted
     * @param string $privateKey
     * @throws SodiumException
     * @throws Exception
     * @dataProvider dataProvider
     */
    public function testDecryption(string $expected, string $encrypted, string $privateKey)
    {
        /* Arrange */
        $core = new Core(false, $privateKey);

        /* Act */
        $decrypted = $core->getDecrypter()->decrypt($encrypted);

        /* Assert */
        $this->assertIsString($decrypted);
        $this->assertSame($expected, $decrypted);
    }

    /**
     * Test the encryption and decryption test.
     *
     * @throws SodiumException
     * @throws Exception
     */
    public function testEncryptionDecryption()
    {
        /* Arrange */
        $core = new Core(true);
        $expected = 'db-value-789';

        /* Act */
        $encrypted = $core->getEncrypter()->encrypt($expected);
        $decrypted = $core->getDecrypter()->decrypt($encrypted);

        /* Assert */
        $this->assertIsString($decrypted);
        $this->assertSame($expected, $decrypted);
    }

    /**
     * Define a data Provider.
     *
     * @return string[][]
     */
    public function dataProvider(): array
    {
        return [
            'decryption 1'  => [
                '0123456789ABCDEF',
                'WyJrT0xSQjZDTm8xQWQrNlRjZGJCS3pTSzdtZWtRbEVSZSIsInRhWUhVc3RGd3VVNk5xSk9iQW1WaFhCNE4wQnVjbUVLMUhoZWdcL0JscTJzPSJd',
                'HQ/xlZakWbE5yVwXeis1ryVoDuz8V4a92GgiUKovkMY='
            ],
            'decryption 2' => [
                'secret-123',
                'WyJ0SG1uMU5STjhtNXUyaU11aUcxMlwvaVNnNEJmcWMzVUoiLCJudmRselljU2V4VlE1ZnZGejJIY1pcL2JNYVRyWlBpNFZMTFk9Il0=',
                'fx0DckMVrmTzxBaW73CTJEkW/tHD4PEFRqdSUEwF1HA='
            ],
            'decryption 3' => [
                'db-value-789',
                'WyJrUGtoNUplaG02Q29lbFRnbDZpa1wvc2h1NkRtR2thdmUiLCJHZWpHT3JFVjZETnlEMnNEMmYrdEhJS0kySFdQNEcySFVkMmhVZz09Il0=',
                'Tb6bhHcnhg622R3DuxIMRoDvzgYK19qZ/1q7ln0veB8='
            ]
        ];
    }
}
