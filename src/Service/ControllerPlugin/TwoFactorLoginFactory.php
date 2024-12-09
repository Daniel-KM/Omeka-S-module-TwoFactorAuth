<?php declare(strict_types=1);

namespace TwoFactorAuth\Service\ControllerPlugin;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorAuth\Mvc\Controller\Plugin\TwoFactorLogin;

class TwoFactorLoginFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        $plugins = $services->get('ControllerPluginManager');

        return new TwoFactorLogin(
            $services->get('Omeka\AuthenticationService'),
            $services->get('Omeka\EntityManager'),
            $services->get('EventManager'),
            $services->get('Omeka\Logger'),
            $services->get('Omeka\Mailer'),
            $plugins->get('messenger'),
            $services->get('Request'),
            $services->get('Omeka\Settings'),
            $plugins->get('translate'),
            $plugins->get('url'),
            $services->get('Omeka\Settings\User'),
            $plugins->get('currentSite')(),
            $services->get('Config')['twofactorauth'],
            class_exists('UserNames\Module')
        );
    }
}
