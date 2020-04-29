<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Ssl\Signer;

use AcmePhp\Ssl\Exception\DataSigningException;
use AcmePhp\Ssl\PrivateKey;
use Webmozart\Assert\Assert;
use AcmePhp\Ssl\PublicKey;
use AcmePhp\Ssl\Exception\DataCheckingSignException;
use AcmePhp\Core\Exception\AcmeCoreClientException;
use Jose\Component\Core\Util\ECSignature;

/**
 * Provide tools to sign data using a private key.
 *
 * @author Titouan Galopin <galopintitouan@gmail.com>
 */
class DataSigner
{
    const FORMAT_DER = 'DER';
    const FORMAT_ECDSA = 'ECDSA';

    /**
     * Generate a signature of the given data using a private key and an algorithm.
     *
     * @param string     $data       Data to sign
     * @param PrivateKey $privateKey Key used to sign
     * @param int        $algorithm  Signature algorithm defined by constants OPENSSL_ALGO_*
     * @param string     $format     Format of the output
     *
     * @return string
     */
    public function signData($data, PrivateKey $privateKey, $algorithm = OPENSSL_ALGO_SHA256, $format = self::FORMAT_DER)
    {
        Assert::oneOf($format, [self::FORMAT_ECDSA, self::FORMAT_DER], 'The format %s to sign request does not exists. Available format: %s');

        $resource = $privateKey->getResource();
        if (!openssl_sign($data, $signature, $resource, $algorithm)) {
            throw new DataSigningException(sprintf('OpenSSL data signing failed with error: %s', openssl_error_string()));
        }

        openssl_free_key($resource);

        switch ($format) {
            case self::FORMAT_DER:
                return $signature;
                break;

            case self::FORMAT_ECDSA:
                switch ($algorithm) {
                    case OPENSSL_ALGO_SHA256:
                        return ECSignature::fromAsn1($signature, 64);
                        break;

                    case OPENSSL_ALGO_SHA384:
                        return ECSignature::fromAsn1($signature, 96);
                        break;

                    case OPENSSL_ALGO_SHA512:
                        return ECSignature::fromAsn1($signature, 132);
                        break;
                }
                throw new DataSigningException('Unable to generate a ECDSA signature with the given algorithm');
                break;

            default:
                throw new DataSigningException('The given format does exists');
                break;
        }
    }

    /**
     * Check sign
     *
     * @param string $signature
     * @param string $data
     * @param PublicKey $publicKey
     * @param int $algorithm
     * @param string $format
     * @return void
     */
    public function checkSign($signature, $data, PublicKey $publicKey, $algorithm = OPENSSL_ALGO_SHA256, $format = self::FORMAT_DER)
    {
        Assert::oneOf($format, [self::FORMAT_ECDSA, self::FORMAT_DER], 'The format %s to sign request does not exists. Available format: %s');

        $resource = $publicKey->getResource();

        switch ($format) {
            case self::FORMAT_DER:
                $signature = $signature;
                break;

            case self::FORMAT_ECDSA:
                switch ($algorithm) {
                    case OPENSSL_ALGO_SHA256:
                        $signature = ECSignature::toAsn1($signature, 64);
                        break;

                    case OPENSSL_ALGO_SHA384:
                        $signature = ECSignature::toAsn1($signature, 96);
                        break;

                    case OPENSSL_ALGO_SHA512:
                        $signature = ECSignature::toAsn1($signature, 132);
                        break;

                    default:
                        throw new DataSigningException('Unable to generate a ECDSA signature with the given algorithm');
                        break;
                }
                break;

            default:
                throw new DataSigningException('The given format does exists');
                break;
        }

        if (1 != openssl_verify($data, $signature, $resource, $algorithm)) {
            throw new DataCheckingSignException(
                sprintf('OpenSSL data checking sign failed with error: %s', openssl_error_string())
            );
        }

        openssl_free_key($resource);
    }

    /**
     * Extract Sign Option From Jws Alg
     *
     * @param string $alg
     * @return array
     */
    public function extractSignOptionFromJWSAlg($alg)
    {
        if (!preg_match('/^([A-Z]+)(\d+)$/', $alg, $match)) {
            throw new AcmeCoreClientException(sprintf('The given "%s" algorithm is not supported', $alg));
        }

        if (!\defined('OPENSSL_ALGO_SHA' . $match[2])) {
            throw new AcmeCoreClientException(sprintf('The given "%s" algorithm is not supported', $alg));
        }

        $algorithm = \constant('OPENSSL_ALGO_SHA' . $match[2]);

        switch ($match[1]) {
            case 'RS':
                $format = static::FORMAT_DER;
                break;
            case 'ES':
                $format = static::FORMAT_ECDSA;
                break;
            default:
                throw new AcmeCoreClientException(sprintf('The given "%s" algorithm is not supported', $alg));
        }

        return [$algorithm, $format];
    }
}
