<?php

namespace League\OAuth2\Client\Provider;
use League\OAuth2\Client\Exception\HostedDomainException;

class GoogleEmailDomainClaim
{
    /**
     * @var array This is used to compare against user's email domain.
     */
    public $domains;

    function __construct($domains) {
        $this->domains = $domains;
    }
    
    /**
     * @throws \DomainException If the email domain is not allowed.
     */
    public function check(GoogleUser $user): void {
        $userEmailDomain = explode("@", $user->getEmail())[1];

        if (in_array($userEmailDomain, $this->domains)) {
            return;
        }

        $domainsString = implode(", ", $this->domains);
        throw HostedDomainException::notMatchingDomain($domainsString);
    }
}
