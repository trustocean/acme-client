<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core;

use AcmePhp\Core\Exception\AcmeCoreClientException;
use AcmePhp\Core\Exception\AcmeCoreServerException;
use AcmePhp\Core\Exception\Protocol\CertificateRequestFailedException;
use AcmePhp\Core\Exception\Protocol\CertificateRevocationException;
use AcmePhp\Core\Exception\Protocol\ChallengeFailedException;
use AcmePhp\Core\Exception\Protocol\ChallengeNotSupportedException;
use AcmePhp\Core\Exception\Protocol\ChallengeTimedOutException;
use AcmePhp\Core\Http\SecureHttpClient;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use AcmePhp\Core\Protocol\CertificateOrder;
use AcmePhp\Core\Protocol\ResourcesDirectory;
use AcmePhp\Core\Protocol\RevocationReason;
use AcmePhp\Ssl\Certificate;
use AcmePhp\Ssl\CertificateRequest;
use AcmePhp\Ssl\CertificateResponse;
use AcmePhp\Ssl\Signer\CertificateRequestSigner;
use Webmozart\Assert\Assert;

/**
 * ACME protocol client implementation.
 *
 * @author Titouan Galopin <galopintitouan@gmail.com>
 */
class AcmeClient implements AcmeClientV2Interface
{
    /**
     * @var SecureHttpClient
     */
    private $uninitializedHttpClient;

    /**
     * @var SecureHttpClient
     */
    private $initializedHttpClient;

    /**
     * @var CertificateRequestSigner
     */
    private $csrSigner;

    /**
     * @var string
     */
    private $directoryUrl;

    /**
     * @var ResourcesDirectory
     */
    private $directory;

    /**
     * @var string
     */
    private $account;

    /**
     * @param SecureHttpClient              $httpClient
     * @param string                        $directoryUrl
     * @param CertificateRequestSigner|null $csrSigner
     */
    public function __construct(SecureHttpClient $httpClient, $directoryUrl, CertificateRequestSigner $csrSigner = null)
    {
        $this->uninitializedHttpClient = $httpClient;
        $this->directoryUrl = $directoryUrl;
        $this->csrSigner = $csrSigner ?: new CertificateRequestSigner();
    }

    /**
     * {@inheritdoc}
     */
    public function getHttpClient()
    {
        if (!$this->initializedHttpClient) {
            $this->initializedHttpClient = $this->uninitializedHttpClient;

            $this->initializedHttpClient->setNonceEndpoint($this->getResourceUrl(ResourcesDirectory::NEW_NONCE));
        }

        return $this->initializedHttpClient;
    }

    /**
     * {@inheritdoc}
     */
    public function registerAccount($agreement = null, $email = null)
    {
        Assert::nullOrString($agreement, 'registerAccount::$agreement expected a string or null. Got: %s');
        Assert::nullOrString($email, 'registerAccount::$email expected a string or null. Got: %s');

        $payload = [
            'termsOfServiceAgreed' => true,
            'contact' => [],
        ];

        if (\is_string($email)) {
            $payload['contact'][] = 'mailto:'.$email;
        }

        $this->requestResource('POST', ResourcesDirectory::NEW_ACCOUNT, $payload);
        $account = $this->getResourceAccount();
        $client = $this->getHttpClient();

        return $client->request('POST', $account, $client->signKidPayload($account, $account, null));
    }

    /**
     * {@inheritdoc}
     */
    public function requestAuthorization($domain)
    {
        $order = $this->requestOrder([$domain]);

        try {
            return $order->getAuthorizationChallenges($domain);
        } catch (AcmeCoreClientException $e) {
            throw new ChallengeNotSupportedException();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function requestOrder(array $domains, $csr = null, $challenge_type = null)
    {
        Assert::allStringNotEmpty($domains, 'requestOrder::$domains expected a list of strings. Got: %s');

        $csrContent = null;
        if ($this->isCsrEager()) {
            $humanText = ['-----BEGIN CERTIFICATE REQUEST-----', '-----END CERTIFICATE REQUEST-----'];
            $csrContent = $this->csrSigner->signCertificateRequest($csr);
            $csrContent = trim(str_replace($humanText, '', $csrContent));
            $csrContent = trim($this->getHttpClient()->getBase64Encoder()->encode(base64_decode($csrContent)));
        }

        $payload = [
            'identifiers' => array_map(
                function ($domain) {
                    return [
                        'type' => 'dns',
                        'value' => $domain,
                    ];
                },
                array_values($domains)
            ),
        ];
        if ($csrContent) {
            $payload['csr'] = $csrContent;
        }
        if ($challenge_type) {
            $payload['challenge_type'] = $challenge_type;
        }

        $client = $this->getHttpClient();
        $resourceUrl = $this->getResourceUrl(ResourcesDirectory::NEW_ORDER);
        $response = $client->request('POST', $resourceUrl, $client->signKidPayload($resourceUrl, $this->getResourceAccount(), $payload));
        if (!isset($response['authorizations']) || !$response['authorizations']) {
            throw new ChallengeNotSupportedException();
        }

        $orderEndpoint = $client->getLastLocation();
        foreach ($response['authorizations'] as $authorizationEndpoint) {
            $authorizationsResponse = $client->request('POST', $authorizationEndpoint, $client->signKidPayload($authorizationEndpoint, $this->getResourceAccount(), null));
            $domain = (empty($authorizationsResponse['wildcard']) ? '' : '*.').$authorizationsResponse['identifier']['value'];
            foreach ($authorizationsResponse['challenges'] as $challenge) {
                $authorizationsChallenges[$domain][] = $this->createAuthorizationChallenge($authorizationsResponse['identifier']['value'], $challenge);
            }
        }

        return new CertificateOrder($authorizationsChallenges, $orderEndpoint);
    }

    /**
     * {@inheritdoc}
     */
    public function reloadAuthorization(AuthorizationChallenge $challenge)
    {
        $client = $this->getHttpClient();
        $challengeUrl = $challenge->getUrl();
        $response = (array) $client->request('POST', $challengeUrl, $client->signKidPayload($challengeUrl, $this->getResourceAccount(), null));

        return $this->createAuthorizationChallenge($challenge->getDomain(), $response);
    }

    /**
     * {@inheritdoc}
     */
    public function challengeAuthorization(AuthorizationChallenge $challenge, $timeout = 180)
    {
        Assert::integer($timeout, 'challengeAuthorization::$timeout expected an integer. Got: %s');

        $endTime = time() + $timeout;
        $client = $this->getHttpClient();
        $challengeUrl = $challenge->getUrl();
        $response = (array) $client->request('POST', $challengeUrl, $client->signKidPayload($challengeUrl, $this->getResourceAccount(), null));
        if ('pending' === $response['status']) {
            $response = (array) $client->request('POST', $challengeUrl, $client->signKidPayload($challengeUrl, $this->getResourceAccount(), []));
        }

        // Waiting loop
        while (time() <= $endTime && (!isset($response['status']) || 'pending' === $response['status'])) {
            sleep(1);
            $response = (array) $client->request('POST', $challengeUrl, $client->signKidPayload($challengeUrl, $this->getResourceAccount(), null));
        }

        if (isset($response['status']) && 'pending' === $response['status']) {
            throw new ChallengeTimedOutException($response);
        }
        if (!isset($response['status']) || 'valid' !== $response['status']) {
            throw new ChallengeFailedException($response);
        }

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function requestCertificate($domain, CertificateRequest $csr, $timeout = 180)
    {
        Assert::stringNotEmpty($domain, 'requestCertificate::$domain expected a non-empty string. Got: %s');
        Assert::integer($timeout, 'requestCertificate::$timeout expected an integer. Got: %s');

        $order = $this->requestOrder(array_unique(array_merge([$domain], $csr->getDistinguishedName()->getSubjectAlternativeNames())));

        return $this->finalizeOrder($order, $csr, $timeout);
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeOrder(CertificateOrder $order, $csr = null, $timeout = 180)
    {
        Assert::integer($timeout, 'finalizeOrder::$timeout expected an integer. Got: %s');

        $endTime = time() + $timeout;
        $client = $this->getHttpClient();
        $orderEndpoint = $order->getOrderEndpoint();
        $response = $client->request('POST', $orderEndpoint, $client->signKidPayload($orderEndpoint, $this->getResourceAccount(), null));
        if (\in_array($response['status'], ['pending', 'ready'])) {
            $csrContent = null;
            if (!$this->isCsrEager()) {
                $humanText = ['-----BEGIN CERTIFICATE REQUEST-----', '-----END CERTIFICATE REQUEST-----'];
    
                $csrContent = $this->csrSigner->signCertificateRequest($csr);
                $csrContent = trim(str_replace($humanText, '', $csrContent));
                $csrContent = trim($client->getBase64Encoder()->encode(base64_decode($csrContent)));
            }
            $response = $client->request('POST', $response['finalize'], $client->signKidPayload($response['finalize'], $this->getResourceAccount(), ['csr' => $csrContent]));
        }

        // Waiting loop
        while (time() <= $endTime && (!isset($response['status']) || \in_array($response['status'], ['pending', 'processing', 'ready']))) {
            sleep(1);
            $response = $client->request('POST', $orderEndpoint, $client->signKidPayload($orderEndpoint, $this->getResourceAccount(), null));
        }

        if ('valid' !== $response['status']) {
            throw new CertificateRequestFailedException('The order has not been validated');
        }

        $response = $client->request('POST', $response['certificate'], $client->signKidPayload($response['certificate'], $this->getResourceAccount(), null), false);
        $certificatesChain = null;
        foreach (array_reverse(explode("\n\n", $response)) as $pem) {
            $certificatesChain = new Certificate($pem, $certificatesChain);
        }

        return new CertificateResponse($csr, $certificatesChain);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeCertificate(Certificate $certificate, RevocationReason $revocationReason = null)
    {
        if (!$endpoint = $this->getResourceUrl(ResourcesDirectory::REVOKE_CERT)) {
            throw new CertificateRevocationException('This ACME server does not support certificate revocation.');
        }

        if (null === $revocationReason) {
            $revocationReason = RevocationReason::createDefaultReason();
        }

        openssl_x509_export(openssl_x509_read($certificate->getPEM()), $formattedPem);

        $formattedPem = str_ireplace('-----BEGIN CERTIFICATE-----', '', $formattedPem);
        $formattedPem = str_ireplace('-----END CERTIFICATE-----', '', $formattedPem);
        $client = $this->getHttpClient();
        $formattedPem = $client->getBase64Encoder()->encode(base64_decode(trim($formattedPem)));

        try {
            $client->request(
                'POST',
                $endpoint,
                $client->signKidPayload($endpoint, $this->getResourceAccount(), ['certificate' => $formattedPem, 'reason' => $revocationReason->getReasonType()]),
                false
            );
        } catch (AcmeCoreServerException $e) {
            throw new CertificateRevocationException($e->getMessage(), $e);
        } catch (AcmeCoreClientException $e) {
            throw new CertificateRevocationException($e->getMessage(), $e);
        }
    }

    /**
     * Find a resource URL.
     *
     * @param string $resource
     *
     * @return string
     */
    public function getResourceUrl($resource)
    {
        if (!$this->directory) {
            $this->directory = new ResourcesDirectory(
                $this->getHttpClient()->request('GET', $this->directoryUrl)
            );
        }

        return $this->directory->getResourceUrl($resource);
    }

    /**
     * Find a resource URL.
     *
     * @return boolean
     */
    public function isCsrEager()
    {
        if (!$this->directory) {
            $this->directory = new ResourcesDirectory(
                $this->getHttpClient()->unsignedRequest('GET', $this->directoryUrl, [], true)
            );
        }

        return $this->directory->isCsrEager();
    }
    /**
     * Request a resource (URL is found using ACME server directory).
     *
     * @param string $method
     * @param string $resource
     * @param array  $payload
     * @param bool   $returnJson
     *
     * @throws AcmeCoreServerException when the ACME server returns an error HTTP status code
     * @throws AcmeCoreClientException when an error occured during response parsing
     *
     * @return array|string
     */
    protected function requestResource($method, $resource, array $payload, $returnJson = true)
    {
        $client = $this->getHttpClient();
        $endpoint = $this->getResourceUrl($resource);

        return $client->request(
            $method,
            $endpoint,
            $client->signJwkPayload($endpoint, $payload),
            $returnJson
        );
    }

    /**
     * Retrieve the resource account.
     *
     * @return string
     */
    private function getResourceAccount()
    {
        if (!$this->account) {
            $payload = [
                'onlyReturnExisting' => true,
            ];

            $this->requestResource('POST', ResourcesDirectory::NEW_ACCOUNT, $payload);
            $this->account = $this->getHttpClient()->getLastLocation();
        }

        return $this->account;
    }

    private function createAuthorizationChallenge($domain, array $response)
    {
        $base64encoder = $this->getHttpClient()->getBase64Encoder();

        return new AuthorizationChallenge(
            $domain,
            $response['status'],
            $response['type'],
            $response['url'],
            $response['token'],
            isset($response['filecontent']) ? $response['filecontent'] : ($response['token'].'.'.$base64encoder->encode($this->getHttpClient()->getJWKThumbprint())),
            isset($response['path']) ? $response['path'] : null,
            isset($response['verifyurl']) ? $response['verifyurl'] : null,
            isset($response['filecontent']) ? $response['filecontent'] : null,
            isset($response['fqdn']) ? $response['fqdn'] : null
        );
    }
}
