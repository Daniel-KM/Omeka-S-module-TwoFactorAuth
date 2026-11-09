<?php declare(strict_types=1);

namespace TwoFactorAuth;

// Common may be installed but not registered in autoloader, in particular
// during upgrade. So dynamically register all classes of the module.
if (!defined('COMMON_PSR4_FALLBACK')) {
    foreach ([
        OMEKA_PATH . '/modules/Common/src',
        OMEKA_PATH . '/composer-addons/modules/Common/src',
        dirname(__DIR__) . '/Common/src',
    ] as $commonSrc) {
        if (file_exists($commonSrc . '/TraitModule.php')) {
            define('COMMON_PSR4_FALLBACK', $commonSrc);
            spl_autoload_register(static function ($class): void {
                if (str_starts_with($class, 'Common\\')) {
                    $file = COMMON_PSR4_FALLBACK . '/' . strtr(substr($class, 7), '\\', '/') . '.php';
                    if (file_exists($file)) {
                        require_once $file;
                    }
                }
            });
            break;
        }
    }
}

use Common\TraitModule;
use Laminas\EventManager\Event;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\ModuleManager\ModuleManager;
use Omeka\Module\AbstractModule;

/**
 * Two Factors Authentification.
 *
 * @copyright Daniel Berthereau, 2024
 * @license http://www.cecill.info/licences/Licence_CeCILL_V2.1-en.txt
 */
class Module extends AbstractModule
{
    use TraitModule;

    const NAMESPACE = __NAMESPACE__;

    protected function preInstall(): void
    {
        $services = $this->getServiceLocator();
        $translator = $services->get('MvcTranslator');

        if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.96')) {
            $message = new \Omeka\Stdlib\Message(
                $translator->translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
                'Common', '3.4.96'
            );
            throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
        }
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager): void
    {
        $sharedEventManager->attach(
            \Omeka\Form\UserForm::class,
            'form.add_elements',
            [$this, 'handleUserSettings']
        );
    }

    public function handleUserSettings(Event $event): void
    {
        $services = $this->getServiceLocator();
        if ($services->get('Omeka\Settings')->get('twofactorauth_force_2fa')) {
            return;
        }

        /** @var \Omeka\Mvc\Status $status */
        $status = $services->get('Omeka\Status');
        if ($status->isAdminRequest()) {
            /** @var \Laminas\Router\Http\RouteMatch $routeMatch */
            $routeMatch = $status->getRouteMatch();
            if (!in_array($routeMatch->getParam('controller'), ['Omeka\Controller\Admin\User', 'user'])) {
                return;
            }
            $this->handleAnySettings($event, 'user_settings');
        }
    }
}
