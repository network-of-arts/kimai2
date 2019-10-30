<?php
declare(strict_types=1);

namespace App\Security;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * @name \App\Security\JwTokenAuthenticator
 * @author     Sergey Kashuba <sk@networkofarts.com>
 * @copyright  Network of Arts AG
 *
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
    public const CLAIM_ROLES         = 'rls';
    public const JWT_CLAIM_USER_MAIL = 'uml';
    public const APP_HOST            = 'APP_HOST';
    public const APP_PROTO           = 'APP_PROTO';
    public const JWT_PUBLIC_KEY      = 'JWT_PUBLIC_KEY';
    public const ROLE_APP_KIMAI      = 'ROLE_APP_KIMAI';

    /**
     * @var EncoderFactoryInterface
     */
    protected $encoderFactory;

    /**
     * @param EncoderFactoryInterface $encoderFactory
     */
    public function __construct(EncoderFactoryInterface $encoderFactory)
    {
        $this->encoderFactory = $encoderFactory;
    }

    /**
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request)
    {
        if (strpos($request->getRequestUri(), '/api/doc') === 0) {
            return false;
        }

        if (strpos($request->getRequestUri(), '/api/') === 0) {
            return $request->cookies->has(self::JWT_COOKIE_NAME);
        }

        return false;
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
        $jwtToken = (new Parser())->parse($credentials['token']);

        if (!$jwtToken->verify(new Sha256(), $_ENV[self::JWT_PUBLIC_KEY])) {
            throw new AuthenticationException('Invalid token signature');
        }

        $data = new ValidationData();
        $data->setIssuer($_ENV[self::APP_HOST]);
        $data->has(self::JWT_CLAIM_USER_MAIL);

        if (!$jwtToken->validate($data)) {
            throw new AuthenticationException('Invalid token');
        }

        $user = $jwtToken->getClaim(self::JWT_CLAIM_USER_MAIL);

        return $userProvider->loadUserByUsername($user);
    }

    /**
     * @param array         $credentials
     * @param UserInterface $user
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        $jwtToken = (new Parser())->parse($credentials['token']);

        return in_array(self::ROLE_APP_KIMAI,
            $jwtToken->getClaim(self::CLAIM_ROLES));
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
     * @return null|JsonResponse|Response
     */
    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ) {
        return new RedirectResponse(sprintf('%s:://portal.%s.com/public/home',
            $_ENV[self::APP_PROTO], $_ENV[self::APP_HOST]), 301);
    }

    /**
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     * @return JsonResponse|Response
     */
    public function start(
        Request $request,
        AuthenticationException $authException = null
    ) {
        print_r($_ENV);

        return new RedirectResponse(sprintf('%s:://portal.%s.com/public/home',
            $_ENV['APP_PROTO'], $_ENV[self::APP_HOST]), 301);
    }

    /**
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }
}