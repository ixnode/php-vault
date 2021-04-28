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

use Ixnode\PhpVault\Exception\PHPVaultUnknownKeyVersionException;
use Ixnode\PhpVault\KeyPair;
use Ixnode\PhpVault\PHPVault;
use Exception;
use Ixnode\PhpVault\Vault\Reader;

class Display
{
    protected Logger $logger;

    /**
     * Display constructor.
     *
     * @param Logger $logger
     */
    public function __construct(Logger $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Indicates that no key was loaded.
     *
     * @return void
     * @throws Exception
     */
    public function noKeyLoaded(): void
    {
        $this->logger->info('No key was loaded.', [], true, true);
    }

    /**
     * Indicates that a private key was loaded.
     *
     * @param PHPVault $phpVaultCore
     * @return void
     * @throws Exception
     */
    public function privateKeyLoaded(PHPVault $phpVaultCore): void
    {
        $this->logger->info('A private key was loaded ({bytes} bytes, version {version}).', array(
            'bytes' => $phpVaultCore->getKeyPair()->loadedSize(),
            'version' => $phpVaultCore->getKeyPair()->getVersionName(),
        ), true, true);
    }

    /**
     * Indicates that a public key was loaded.
     *
     * @param PHPVault $phpVaultCore
     * @return void
     * @throws Exception
     */
    public function publicKeyLoaded(PHPVault $phpVaultCore): void
    {
        $this->logger->info('A public key was loaded ({bytes} bytes, version {version}).', array(
            'bytes' => $phpVaultCore->getKeyPair()->loadedSize(),
            'version' => $phpVaultCore->getKeyPair()->getVersionName(),
        ), true, true);
    }

    /**
     * Indicates the place where the key was loaded from.
     *
     * @param KeyPair $keyPair
     * @throws Exception
     */
    public function keyLoadedFrom(KeyPair $keyPair): void
    {
        $templateFile = 'The key was loaded from given file: {from-path}';
        $templateEnvironment = 'The key was loaded from environment: {from-environment}.';
        $templatePassedString = 'The key was loaded from passed string.';
        $templateRandomGenerator = 'The key was loaded from random generator.';

        $setting = array(
            'from-source' => $keyPair->loadedFromSource() ?: '',
            'from-path' => $keyPair->loadedFromPath() ?: '',
            'from-environment' => $keyPair->loadedFromEnvironment() ?: '',
        );

        switch ($keyPair->loadedFromSource()) {
            case KeyPair::LOADED_FROM_FILE:
                    $this->logger->info($templateFile, $setting, true, true);
                break;
            case KeyPair::LOADED_FROM_ENVIRONMENT:
                $this->logger->info($templateEnvironment, $setting, true, true);
                break;
            case KeyPair::LOADED_FROM_PASSED_STRING:
                $this->logger->info($templatePassedString, $setting, true, true);
                break;
            case KeyPair::LOADED_FROM_RANDOM_GENERATOR:
                $this->logger->info($templateRandomGenerator, $setting, true, true);
                break;
            default:
                throw new Exception(sprintf('Unknown source "%s".', $keyPair->loadedFromSource()));
        }
    }

    /**
     * Indicates that given file was not found.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function fileNotFound(string $file): void
    {
        $this->logger->error('The given file "{file}" was not found.', array('file' => $file, ), true, true);
    }

    /**
     * Indicates that no env file was given.
     *
     * @return void
     * @throws Exception
     */
    public function noEnvFileGiven(): void
    {
        $this->logger->error('No env file was given. Please specify one.', [], true, true);
    }

    /**
     * Indicates that the given file already exists.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function fileAlreadyExists(string $file): void
    {
        $this->logger->error('File "{file}" already exist. Abort.', ['file' => $file, ], true, true);
    }

    /**
     * Indicates that an error occurred while trying to write the given file.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function writeFileErrorOccurred(string $file): void
    {
        $this->logger->error('An error occurred while trying to write the env file "{file}".', ['file' => $file, ], true, true);
    }

    /**
     * Indicates that the given file was successfully written.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function fileSuccessfullyWritten(string $file): void
    {
        $this->logger->info('The file was successfully written to "{file}".', ['file' => $file, ], true, true);
    }

    /**
     * Indicates that given file was already encrypted.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function fileAlreadyEncrypted(string $file): void
    {
        $this->logger->warn('The given file "{file}" seems already be encrypted. Abort.', array('file' => $file, ));
    }

    /**
     * Indicates that given file has the wrong format.
     *
     * @param string $file
     * @return void
     * @throws Exception
     */
    public function fileEncryptedWrongFormat(string $file): void
    {
        $this->logger->warn('The given file "{file}" must have the following format: "*.enc". Abort.', array('file' => $file, ));
    }

    /**
     * Returns the private and public key according to its given version.
     *
     * @param PHPVault $phpVaultCore
     * @param string $version
     * @return string[]|null[]
     * @throws PHPVaultUnknownKeyVersionException
     */
    protected function getPrivateAndPublicKey(PHPVault $phpVaultCore, string $version): array
    {
        switch ($version) {
            case 'v1':
                return [
                    $phpVaultCore->getKeyPair()->getPrivateKey(),
                    $phpVaultCore->getKeyPair()->getPublicKey(),
                ];

            case 'v2':
                return [
                    $phpVaultCore->getKeyPair()->getPrivateKeyCombined(),
                    $phpVaultCore->getKeyPair()->getPublicKeyCombined()
                ];

            default:
                throw new PHPVaultUnknownKeyVersionException();
        }
    }

    /**
     * Displays the private and public keys.
     *
     * @param PHPVault $phpVaultCore
     * @param string $version
     * @return void
     * @throws PHPVaultUnknownKeyVersionException
     */
    public function privateAndPublicKeys(PHPVault $phpVaultCore, string $version): void
    {
        $this->logger->getWriter()->table([
            ['name' => 'private key', 'value' => $phpVaultCore->getKeyPair()->getPrivateKeyByVersion($version)],
            ['name' => 'public key', 'value' => $phpVaultCore->getKeyPair()->getPublicKeyByVersion($version)],
            ['name' => 'version', 'value' => $version]
        ]);
    }

    /**
     * Displays all environment variables from given file.
     *
     * @param PHPVault $phpVaultCore
     * @param string $outputType
     * @return void
     * @throws Exception
     */
    public function envVariables(PHPVault $phpVaultCore, string $outputType = Reader::OUTPUT_TO_ENCRYPTED): void
    {
        $table = array();

        /* Collect all environment variables. */
        foreach ($phpVaultCore->getVault()->getAllKeyValuePairsRaw(true) as $key => $data) {
            $table[] = [
                'key' => $key,
                'value' => $outputType === Reader::OUTPUT_TO_DECRYPTED ? $data->getValueDecrypted() : $data->getValueEncrypted(),
                'description' => $outputType === Reader::OUTPUT_TO_DECRYPTED ? $data->getDescriptionDecrypted(): $data->getDescriptionEncrypted(),
            ];
        }

        /* Set styles. */
        $styles = [
            'head' => 'bold',
            'odd' => 'yellow',
            'even' => 'green'
        ];

        /* Print table. */
        $this->logger->getWriter()->table($table, $styles);
    }

    /**
     * Displays all server environment variables.
     *
     * @return void
     */
    public function serverEnvVariables(): void
    {
        $table = array();

        /* Collect all environment variables. */
        foreach ($_SERVER as $name => $value) {
            if (gettype($value) !== 'string') {
                continue;
            }

            $table[] = [
                'name' => $name,
                'value' => $value,
            ];
        }

        /* Set styles. */
        $styles = [
            'head' => 'bold',
            'odd' => 'yellow',
            'even' => 'green'
        ];

        /* Print table. */
        $this->logger->getWriter()->table($table, $styles);
    }
}
