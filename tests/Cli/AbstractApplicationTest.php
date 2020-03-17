<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\AcmePhp\Cli;

use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Tests\AcmePhp\Cli\Mock\AbstractTestApplication;
use Tests\AcmePhp\Cli\Mock\SimpleApplication;
use Tests\AcmePhp\Core\AbstractFunctionnalTest;
use Webmozart\PathUtil\Path;

abstract class AbstractApplicationTest extends AbstractFunctionnalTest
{
    /**
     * @var AbstractTestApplication
     */
    protected $application;

    /**
     * @return array
     */
    abstract protected function getFixturesDirectories();

    /**
     * @return AbstractTestApplication
     */
    abstract protected function createApplication();

    public function setUp()
    {
        $this->cleanContext();

        $this->application = $this->createApplication();
    }

    public function tearDown()
    {
        $this->cleanContext();
    }

    public function testFullProcess()
    {
        /*
         * Register
         */
        $register = $this->application->find('register');
        $registerTester = new CommandTester($register);
        $registerTester->execute([
            'command' => $register->getName(),
            'email' => 'foo@example.com',
            '--server' => 'https://localhost:14000/dir',
        ]);

        $registerDisplay = $registerTester->getDisplay();

        $this->assertStringContainsString('No account key pair was found, generating one', $registerDisplay);
        $this->assertStringContainsString('Account registered successfully', $registerDisplay);
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/account/key.private.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/account/key.public.pem');

        /*
         * Authorize
         */
        $authorize = $this->application->find('authorize');
        $authorizeTest = new CommandTester($authorize);
        $authorizeTest->execute([
            'command' => $authorize->getName(),
            'domains' => ['acmephp.com'],
            '--server' => 'https://localhost:14000/dir',
        ]);

        $authorizeDisplay = $authorizeTest->getDisplay();

        $this->assertStringContainsString('The authorization tokens was successfully fetched', $authorizeDisplay);
        $this->assertStringContainsString('http://acmephp.com/.well-known/acme-challenge/', $authorizeDisplay);
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/var/acmephp.com/authorization_challenge.json');

        /*
         * Check
         */

        // Find challenge and expose token
        $challenge = json_decode(
            file_get_contents(__DIR__.'/../Cli/Fixtures/local/master/var/acmephp.com/authorization_challenge.json'),
            true
        );

        $this->handleChallenge($challenge['token'], $challenge['payload']);
        try {
            $check = $this->application->find('check');
            $checkTest = new CommandTester($check);
            $checkTest->execute([
                'command' => $check->getName(),
                'domains' => ['acmephp.com'],
                '--server' => 'https://localhost:14000/dir',
                '--no-test' => null,
            ]);

            $checkDisplay = $checkTest->getDisplay();

            $this->assertStringContainsString('The authorization check was successful', $checkDisplay);
        } finally {
            $this->cleanChallenge($challenge['token']);
        }

        /*
         * Request
         */
        $request = $this->application->find('request');
        $requestTest = new CommandTester($request);
        $requestTest->execute([
            'command' => $request->getName(),
            'domain' => 'acmephp.com',
            '--server' => 'https://localhost:14000/dir',
            '--country' => 'FR',
            '--province' => 'Ile de France',
            '--locality' => 'Paris',
            '--organization' => 'Acme PHP',
            '--unit' => 'Sales',
            '--email' => 'example@acmephp.github.io',
        ]);

        $requestDisplay = $requestTest->getDisplay();

        $this->assertStringContainsString('The SSL certificate was fetched successfully', $requestDisplay);
        $this->assertStringContainsString(Path::canonicalize(__DIR__.'/Fixtures/local/master'), $requestDisplay);
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/private/key.private.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/private/key.public.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/public/cert.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/private/combined.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/public/chain.pem');
        $this->assertFileExists(__DIR__.'/../Cli/Fixtures/local/master/certs/acmephp.com/public/fullchain.pem');
    }

    public function testCheckWithoutKeyFail()
    {
        $this->expectException('AcmePhp\Cli\Exception\CommandFlowException');
        $this->application = new SimpleApplication();

        $command = $this->application->find('check');
        $commandTester = new CommandTester($command);
        $commandTester->execute([
            'command' => $command->getName(),
            'domains' => ['example.com'],
            '--server' => 'https://localhost:14000/dir',
        ]);
    }

    public function testAuthorizeWithoutKeyFail()
    {
        $this->expectException('AcmePhp\Cli\Exception\CommandFlowException');
        $this->application = new SimpleApplication();

        $command = $this->application->find('authorize');
        $commandTester = new CommandTester($command);
        $commandTester->execute([
            'command' => $command->getName(),
            'domains' => 'example.com',
            '--server' => 'https://localhost:14000/dir',
        ]);
    }

    public function testRequestWithoutKeyFail()
    {
        $this->expectException('AcmePhp\Cli\Exception\CommandFlowException');
        $this->application = new SimpleApplication();

        $command = $this->application->find('request');
        $commandTester = new CommandTester($command);
        $commandTester->execute([
            'command' => $command->getName(),
            'domain' => 'acmephp.com',
            '--server' => 'https://localhost:14000/dir',
            '--country' => 'FR',
            '--province' => 'Ile de France',
            '--locality' => 'Paris',
            '--organization' => 'Acme PHP',
            '--unit' => 'Sales',
            '--email' => 'example@acmephp.github.io',
        ]);
    }

    /**
     * Remove fixtures files and directories to have a clean context.
     */
    private function cleanContext()
    {
        $filesystem = new Filesystem();
        $finder = new Finder();

        $filesystem->remove(
            $finder
                ->in($this->getFixturesDirectories())
                ->notName('.gitkeep')
                ->getIterator()
        );
    }
}
