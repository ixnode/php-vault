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
use Ixnode\PhpVault\PHPVault;
use Exception;
use SodiumException;

final class PHPVaultTest extends TestCase
{
    /**
     * Test decryption.
     *
     * @param string $expected
     * @param string $encrypted
     * @param string $privateKey
     * @return void
     * @throws SodiumException
     * @throws Exception
     * @dataProvider dataProvider
     */
    public function testDecryption(string $expected, string $encrypted, string $privateKey): void
    {
        /* Arrange */
        $core = new PHPVault(false, $privateKey);

        /* Act */
        $decrypted = $core->getDecrypter()->decrypt($encrypted);

        /* Assert */
        $this->assertIsString($decrypted);
        $this->assertSame($expected, $decrypted);
    }

    /**
     * Test the encryption and decryption test.
     *
     * @return void
     * @throws SodiumException
     * @throws Exception
     */
    public function testEncryptionDecryption(): void
    {
        /* Arrange */
        $core = new PHPVault(true);
        $expected = 'db-value-789';

        /* Act */
        $encrypted = $core->getEncrypter()->encrypt($expected);
        $decrypted = $encrypted === null ? null : $core->getDecrypter()->decrypt($encrypted);

        /* Assert */
        $this->assertIsString($encrypted);
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
            /* Encrypted with version 1 of public and private key  */
            'decryption 1 - v1'  => [
                '0123456789ABCDEF',
                'WyJrT0xSQjZDTm8xQWQrNlRjZGJCS3pTSzdtZWtRbEVSZSIsInRhWUhVc3RGd3VVNk5xSk9iQW1WaFhCNE4wQnVjbUVLMUhoZWdcL0JscTJzPSJd',
                'HQ/xlZakWbE5yVwXeis1ryVoDuz8V4a92GgiUKovkMY=' /* private key v1 */
            ],
            'decryption 2 - v1' => [
                'secret-123',
                'WyJ0SG1uMU5STjhtNXUyaU11aUcxMlwvaVNnNEJmcWMzVUoiLCJudmRselljU2V4VlE1ZnZGejJIY1pcL2JNYVRyWlBpNFZMTFk9Il0=',
                'fx0DckMVrmTzxBaW73CTJEkW/tHD4PEFRqdSUEwF1HA=' /* private key v1 */
            ],
            'decryption 3 - v1' => [
                'db-value-789',
                'WyJrUGtoNUplaG02Q29lbFRnbDZpa1wvc2h1NkRtR2thdmUiLCJHZWpHT3JFVjZETnlEMnNEMmYrdEhJS0kySFdQNEcySFVkMmhVZz09Il0=',
                'Tb6bhHcnhg622R3DuxIMRoDvzgYK19qZ/1q7ln0veB8=' /* private key v1 */
            ],

            /* Encrypted with version 2 of public and private key  */
            'decryption 1 - v2'  => [
                '0123456789ABCDEF',
                'WyJTN21XN2Q2UzRNXC9wNkNLc09ONHlveU5vVVpYZWgySjkiLCIrV1dcL1lraXJHODhTc05hZTliQ0NFYXFmUEdUTUhNV2pMaXU2VTRISkRDST0iXQ==',
                'WyJUTE9qOUZwVWxYZjhLTFNFaUlnS3BOQllncE5IMXRWSlk1TFVtOU5INzNjPSIsIjU0ZTFiMmJkYjYwYjgwZDVkMzBmY2UzYjFkNzE4MjIxIl0=' /* private key v2 */
            ],
            'decryption 2 - v2' => [
                'secret-123',
                'WyJBdlFSdmVIT0owMXU0VzQzTW9uT1lMZG9ZbGVjTjhBaiIsIm91Sk01bHBVSStJU2E5bDVZRVl3U0xFTE80UXdsM2VGWXg4PSJd',
                'WyJyNE14eEcxanExb1NENU5UT1IxbDdxRTYwSnM0UkI2dEpBNmJYRytmRUIwPSIsImZkYjE0YWQ1Njc2ODEyYTQ2MDRkN2U3MWZhZTQ1MzU0Il0=' /* private key v2 */
            ],
            'decryption 3 - v2' => [
                'db-value-789',
                'WyJRd29GXC9WcU9ac01NZnREa0NvKzhydU1JTGlHZ2M5RmgiLCJzVDltakRjMGMzODZVOHM1ekJtYmZhV1wvZ0VqUm1oYWN6KzhlTXc9PSJd',
                'WyJcL0RFYzRDYm1WNkpxcWU5YklKUExJZDV2WXhXQWF5eXVCbncxVHhRNlNRZz0iLCI3N2FlN2Q3NWRiM2JmMzVjYzk0NmFlODMxYzQ2ZDc2OCJd' /* private key v2 */
            ],
        ];
    }
}
