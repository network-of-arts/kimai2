<?php

declare(strict_types=1);

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Security;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * @name \App\Security\JwTokenAuthenticator
 * @author     Sergey Kashuba <sk@networkofarts.com>
 * @copyright  Network of Arts AG
 */
class JwTokenAuthenticator extends AbstractGuardAuthenticator
{

    /**
     * @var string the default cookie name containing the jwt token
     */
    public const JWT_COOKIE_NAME = 'jwt';
    /**
     * @var string the claim that contains the roles
     */
    public const CLAIM_ROLES = 'rls';
    /**
     * @var string the claim that contains the extensions
     */
    public const JWT_CLAIM_EXTENSIONS = 'ext';
    /**
     * @var string the claim that contains user login in kimai
     */
    public const JWT_CLAIM_USER_MAIL = 'uml';
    /**
     * @var string key of application host
     */
    public const APP_HOST = 'APP_HOST';
    /**
     * @var string key of application protocol
     */
    public const        APP_PROTO = 'APP_PROTO';
    /**
     * @var string role for kimai user
     */
    public const        ROLE_APP_KIMAI = 'ROLE_EMPLOYEE';
    /**
     * @var string public key for decoding
     */
    public const JWT_PUBLIC_KEY = <<<KEY
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGoMv8P6xVNliDnqNvBf
gSHsoB7KMqx01RImoEzRwglXVjTTKM2PNdhb+KLOag5LrWsaNk4yVBb7aHQEzcTK
gYGMNpEEigKLqO+Eb8zGuQExYv+kKh84I3o8SuVFVsyz98MHpJ4u7xDeNphkysoe
tk8VCrLQ9vcARXd9LvKbpWwqwv/3USPxEYtmeYPh/lhB0OpOvgs/dfWD4Gahmkrn
QURYnIfaHTXN/YkH21mNbPjWiEkS/lfJDkIuVlQ/+xlleKYklU/1L5AKxECOWQyN
jHfz1JQxOxJ5zS3uxRwOSF9s7WQsPhKWK9m3IvHmfm98fyp8O+UTewZMeE65unpC
CwIDAQAB
-----END PUBLIC KEY-----
KEY;
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * JwTokenAuthenticator constructor.
     *
     * @param \Psr\Log\LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request)
    {
        // we support every request - no other auth method is allowed
        return true;
    }

    /**
     * @param Request $request
     * @return array
     */
    public function getCredentials(Request $request)
    {
        return [
            'token' => $request->cookies->get(self::JWT_COOKIE_NAME),
        ];
    }

    /**
     * @param array                 $credentials
     * @param UserProviderInterface $userProvider
     * @return null|UserInterface
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $jwtToken = (new Parser())->parse($credentials['token']);
            if (!$jwtToken->verify(new Sha256(), self::JWT_PUBLIC_KEY)) {
                $this->logger->error('JWT has invalid signature');
                throw new AuthenticationException('Invalid token signature');
            }

            $ext = $jwtToken->getClaim(self::JWT_CLAIM_EXTENSIONS);
            $key = self::JWT_CLAIM_USER_MAIL;
            $user = $ext->$key;

            return $userProvider->loadUserByUsername($user);
        } catch (\Exception $exception) {
            var_dump($exception->getMessage());
            throw new AuthenticationException('Unable to parse token');
        }
    }

    /**
     * @param array         $credentials
     * @param UserInterface $user
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        $jwtToken = (new Parser())->parse($credentials['token']);

        return in_array(
            strtolower(self::ROLE_APP_KIMAI),
            $jwtToken->getClaim(self::CLAIM_ROLES)
        );
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     * @return null|Response
     */
    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        $providerKey
    ) {
        return null;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     * @return RedirectResponse
     */
    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ) {
        $data = [
            'message' => 'Invalid token'
            // security measure: do not leak real reason (unknown user, invalid credentials ...)
            // you can uncomment this for debugging
            // 'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        ];

        $url = sprintf(
            '%s://portal.networkofarts.com/public/home',
            getenv(self::APP_PROTO)
        );
        var_dump($exception);
        die('Redirect to portal');

        return new RedirectResponse(
            $url,
            301
        );
    }

    /**
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     * @return RedirectResponse|Response
     */
    public function start(
        Request $request,
        AuthenticationException $authException = null
    ) {
        $url = sprintf(
            '%s://portal.networkofarts.com/public/home',
            getenv(self::APP_PROTO)
        );
        var_dump($authException);
        die('Redirect to portal');

        return new RedirectResponse(
            $url,
            301
        );
    }

    /**
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }
}
