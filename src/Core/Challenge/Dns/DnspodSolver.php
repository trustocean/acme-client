<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Dns;

use AcmePhp\Core\Challenge\ConfigurableServiceInterface;
use AcmePhp\Core\Challenge\Dns\Traits\TopLevelDomainTrait;
use AcmePhp\Core\Challenge\MultipleChallengesSolverInterface;
use AcmePhp\Core\Exception\AcmeCoreClientException;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Webmozart\Assert\Assert;

use function GuzzleHttp\json_decode;
use function GuzzleHttp\json_encode;

/**
 * ACME DNS solver with automate configuration of a DnsPod.cn (TencentCloud NS).
 *
 * @author Xiaohui Lam <xiaohui.lam@e.hexdata.cn>
 * @link https://www.dnspod.cn/docs/records.html#record-list
 */
class DnspodSolver implements MultipleChallengesSolverInterface, ConfigurableServiceInterface
{
    use LoggerAwareTrait, TopLevelDomainTrait;

    /**
     * @var DnsDataExtractor
     */
    private $extractor;

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var array
     */
    private $cacheZones;

    /**
     * @var int
     */
    private $id;

    /**
     * @var string
     */
    private $token;

    /**
     * 批量ID
     *
     * @var int
     */
    private $job_id;

    /**
     * @param DnsDataExtractor $extractor
     * @param ClientInterface  $client
     */
    public function __construct(
        DnsDataExtractor $extractor = null,
        ClientInterface $client = null
    ) {
        $this->extractor = null === $extractor ? new DnsDataExtractor() : $extractor;
        $this->client = null === $client ? new Client() : $client;
        $this->logger = new NullLogger();
    }

    /**
     * Configure the service with a set of configuration.
     *
     * @param array $config
     */
    public function configure(array $config)
    {
        $this->id = $config['id'];
        $this->token = $config['token'];
    }

    /**
     * {@inheritdoc}
     */
    public function supports(AuthorizationChallenge $authorizationChallenge)
    {
        return 'dns-01' === $authorizationChallenge->getType();
    }

    /**
     * {@inheritdoc}
     */
    public function solve(AuthorizationChallenge $authorizationChallenge)
    {
        return $this->solveAll([$authorizationChallenge]);
    }

    /**
     * {@inheritdoc}
     */
    public function solveAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        $domains = [];
        $records_all = [];

        $http = new Client();

        $domainListResponse = $http->post('https://dnsapi.cn/Domain.List', [
            RequestOptions::FORM_PARAMS => [
                'format' => 'json',
                'login_token' => implode(',', [$this->id, $this->token]),
                'length' => 2000,
            ],
        ]);
        if ($domainListResponse->getStatusCode() == 200) {
            $domainList = json_decode($domainListResponse->getBody()->__toString(), true);
            foreach ($domainList['domains'] as $domain) {
                $domains[$domain['name']] = $domain['id'];
            }
        }

        foreach ($authorizationChallenges as $authorizationChallenge) {
            $recordType = 'txt';
            if (method_exists($this->extractor, 'getRecordType')) {
                $recordType = $this->extractor->getRecordType($authorizationChallenge);
            }
            $listResponse = $http->post('https://dnsapi.cn/Record.List', [
                RequestOptions::FORM_PARAMS => [
                    'format' => 'json',
                    'login_token' => implode(',', [$this->id, $this->token]),
                    'domain' => $this->getTopLevelDomain($authorizationChallenge->getDomain()),
                    'sub_domain' => preg_replace('/\.' . str_replace('.', '\.', $this->getTopLevelDomain($authorizationChallenge->getDomain())) . '$/', '', $this->extractor->getRecordFqdn($authorizationChallenge)),
                    'record_type' => $recordType,
                ],
            ]);
            $list = json_decode($listResponse->getBody()->__toString(), true);
            if ($listResponse->getStatusCode() == 200 && $list['status']['code'] == 1) {
                $domain = $list['domain'];
                $domains[$this->getTopLevelDomain($authorizationChallenge->getDomain())] = $domain['id'];
                if ('cname' === strtolower($recordType)) {
                    if (isset($list['records']) && is_array($list['records'])) {
                        $records = $list['records'];
                        foreach ($records as $record) {
                            $this->logger->debug('Fetched Conflict records for domain, deleting', [
                                'domain' => $this->getTopLevelDomain($authorizationChallenge->getDomain()),
                                'record_type' => $recordType,
                                'record_id' => $record['id'],
                            ]);

                            $http->post('https://dnsapi.cn/Record.Remove', [
                                RequestOptions::FORM_PARAMS => [
                                    'format' => 'json',
                                    'login_token' => implode(',', [$this->id, $this->token]),
                                    'domain' => $this->getTopLevelDomain($authorizationChallenge->getDomain()),
                                    'record_id' => $record['id'],
                                ],
                            ]);
                        }
                    }
                }
            }

            $arr = [
                'sub_domain' => preg_replace('/\.' . str_replace('.', '\.', $this->getTopLevelDomain($authorizationChallenge->getDomain())) . '$/', '', $this->extractor->getRecordFqdn($authorizationChallenge)),
                'record_type' => $recordType,
                'record_line' => '默认',
                'value' => $this->extractor->getRecordValue($authorizationChallenge),
                'ttl' => 600,
            ];
            $records_all[md5(http_build_query($arr))] = $arr;
        }

        sort($records_all);
        sort($domains);

        $this->logger->debug('Batch creating for domains', $domains);
        $this->logger->debug('Batch creating records', $records_all);
        $batchrResponse = $http->post('https://dnsapi.cn/Batch.Record.Create', [
            RequestOptions::FORM_PARAMS => [
                'format' => 'json',
                'login_token' => implode(',', [$this->id, $this->token]),
                'domain_id' => implode(',', $domains),
                'records' => json_encode($records_all),
            ],
        ]);

        $batch = json_decode($batchrResponse->getBody()->__toString(), true);
        if ($batch['status']['code'] != 1) {
            throw new AcmeCoreClientException('Resolving domain fail!', new \Exception($batch['status']['message'], (int) $batch['status']['code']));
        }
        $this->job_id = $batch['job_id']; // log job id, after cert issued, it should be using to cleanup
    }

    /**
     * {@inheritdoc}
     */
    public function cleanup(AuthorizationChallenge $authorizationChallenge)
    {
        return $this->cleanupAll([$authorizationChallenge]);
    }

    /**
     * {@inheritdoc}
     */
    public function cleanupAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        cleanup:
        $http = new Client();
        $batchrResponse = $http->post('https://dnsapi.cn/Batch.Detail', [
            RequestOptions::FORM_PARAMS => [
                'format' => 'json',
                'login_token' => implode(',', [$this->id, $this->token]),
                'job_id' => $this->job_id,
            ],
        ]);
        $batch = json_decode($batchrResponse->getBody()->__toString(), true);

        foreach ($batch['detail'] as $tld) {
            if ($tld['status'] == 'running' || $tld['status'] == 'waiting') {
                $this->logger->debug('Batch task status ' . $tld['status'], $tld);
                sleep(5);
                goto cleanup;
            }

            if ($tld['status'] == 'error') {
                $this->logger->debug('Batch task status ' . $tld['status'], $tld);
                continue;
                // @TODO:
            }

            if ($tld['status'] == 'ok') {
                $records = $tld['records'];

                foreach ($records as $record) {
                    $http->post('https://dnsapi.cn/Record.Remove', [
                        RequestOptions::FORM_PARAMS => [
                            'format' => 'json',
                            'login_token' => implode(',', [$this->id, $this->token]),
                            'domain_id' => $tld['id'],
                            'record_id' => $record['id'],
                        ],
                    ]);
                }
            }
        }
    }
}
