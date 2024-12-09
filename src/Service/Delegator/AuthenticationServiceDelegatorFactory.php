<?php declare(strict_types=1);

namespace TwoFactorAuth\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use Omeka\Authentication\Adapter\KeyAdapter;
use Omeka\Entity\User;
use TwoFactorAuth\Authentication\Adapter\TokenAdapter;
use TwoFactorAuth\Entity\Token;

class AuthenticationServiceDelegatorFactory implements DelegatorFactoryInterface
{
    public function __invoke(
        ContainerInterface $services,
        $name,
        callable $callback,
        ?array $options = null
    ) {
        /**
         * @var \Laminas\Authentication\AuthenticationService $authenticationService
         * @var \Omeka\Authentication\Adapter\PasswordAdapter|\Guest\Authentication\Adapter\PasswordAdapter|\UserNames\Authentication\Adapter\PasswordAdapter $adapter
         * @var \Doctrine\ORM\EntityManager $entityManager
         *
         * @see \Omeka\Service\AuthenticationServiceFactory
         */
        $authenticationService = $callback();

        // Nothing to do if the adapter is the one for api.
        $adapter = $authenticationService->getAdapter();
        if ($adapter instanceof KeyAdapter) {
            return $authenticationService;
        }

        $settings = $services->get('Omeka\Settings');
        $entityManager = $services->get('Omeka\EntityManager');

        $tokenAdapter = new TokenAdapter(
            $adapter,
            $services->get('Omeka\Connection'),
            $services->get('Omeka\EntityManager'),
            $entityManager->getRepository(Token::class),
            $entityManager->getRepository(User::class),
            $services->get('Omeka\Settings\User'),
            (int) $settings->get('twofactorauth_expiration_duration') ?: 1200,
            (bool) $settings->get('twofactorauth_force_2fa')
        );

        $storage = $authenticationService->getStorage();

        return $authenticationService
            ->setAdapter($tokenAdapter)
            ->setStorage($storage)
        ;
    }
}
