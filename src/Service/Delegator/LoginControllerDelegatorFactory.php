<?php declare(strict_types=1);

namespace TwoFactorAuth\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use TwoFactorAuth\Controller\LoginController;

class LoginControllerDelegatorFactory implements DelegatorFactoryInterface
{
    public function __invoke(
        ContainerInterface $services,
        $name,
        callable $callback,
        ?array $options = null
    ) {
        /**
         * @var \Omeka\Controller\LoginController|\Guest\Controller\Site\AnonymousController|\Lockout\Controller\LoginController|\UserNames\Controller\LoginController $loginController
         * @see \Omeka\Service\Controller\LoginControllerFactory
         *
         * Lockout checks if the ip is restricted before login.
         * UserNames controller uses a specific LoginForm to allow to log with user name.
         */
        $loginController = $callback();

        return new LoginController(
            $loginController,
            $services->get('Omeka\AuthenticationService'),
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\ApiAdapterManager')->get('users'),
            $services->get('Config')['twofactorauth']
        );
    }
}
