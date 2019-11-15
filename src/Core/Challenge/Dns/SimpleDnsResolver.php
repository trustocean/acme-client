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

/**
 * Resolves DNS through dns_get_record.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class SimpleDnsResolver implements DnsResolverInterface
{
    /**
     * @{@inheritdoc}
     */
    public static function isSupported()
    {
        return \function_exists('dns_get_record');
    }

    /**
     * @{@inheritdoc}
     */
    public function getTxtEntries($domain)
    {
        $entries = [];
        foreach (dns_get_record($domain, DNS_TXT) as $record) {
            $entries = array_merge($entries, $record['entries']);
        }

        sort($entries);

        return array_unique($entries);
    }

    public function getEnteries($type, $domain)
    {
        $entries = [];
        $type_int = null;
        switch (strtolower($type)) {
            case 'cname':
                $type_int = DNS_CNAME;
                break;

            case 'a':
                $type_int = DNS_A;
                break;

            case 'txt':
                $type_int = DNS_TXT;
                break;

            default:
                throw new Exception("Doesn't support type ".$type, 0);
                break;
        }

        foreach (dns_get_record($domain, $type_int) as $record) {
            $entries = array_merge($entries, $record['entries']);
        }

        sort($entries);

        return array_unique($entries);
    }
}
