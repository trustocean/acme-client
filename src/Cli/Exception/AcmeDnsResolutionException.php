<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Cli\Exception;

@trigger_error(sprintf('The "%s" class is deprecated since version 1.1 and will be removed in 2.0., use %s instead.', AcmeDnsResolutionException::class, \AcmePhp\Core\Exception\AcmeDnsResolutionException::class), E_USER_DEPRECATED);

/**
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class AcmeDnsResolutionException extends AcmeCliException
{
    public function __construct($message, \Exception $previous = null)
    {
        parent::__construct(null === $message ? 'An exception was thrown during resolution of DNS' : $message, $previous);
    }
}
