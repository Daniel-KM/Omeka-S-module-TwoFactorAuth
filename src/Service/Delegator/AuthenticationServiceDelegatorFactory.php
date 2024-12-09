<?php declare(strict_types=1);

namespace TwoFactorAuth\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use Omeka\Authentication\Adapter\KeyAdapter;
use TwoFactorAuth\Authentication\Adapter\TokenAdapter;
use TwoFactorAuth\Entity\TfaToken;

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

        $entityManager = $services->get('Omeka\EntityManager');
        $tfaTokenRepository = $entityManager->getRepository(TfaToken::class);
        $tokenAdapter = new TokenAdapter(
            $adapter,
            $services->get('Omeka\Connection'),
            $tfaTokenRepository,
            $services->get('Omeka\Settings\User')
        );

        $storage = $authenticationService->getStorage();

        return $authenticationService
            ->setAdapter($tokenAdapter)
            ->setStorage($storage)
        ;
    }
}
