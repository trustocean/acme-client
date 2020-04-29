<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Dns\Traits;

use DateInterval;
use Pdp\Cache;
use Pdp\CurlHttpClient;
use Pdp\Manager;

trait TopLevelDomainTrait
{
    /**
     * @param string $domain
     *
     * @return string
     */
    protected function getTopLevelDomain($domain)
    {
        $manager = new Manager(new Cache(), new CurlHttpClient(), (new DateInterval('365d')));
        $rules = $manager->getRules();

        $resolve = $rules->resolve($domain);

        return $resolve->getRegistrableDomain();
    }
}
