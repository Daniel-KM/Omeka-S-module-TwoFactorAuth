<?php declare(strict_types=1);

namespace TwoFactorAuthTest\Controller;

use CommonTest\AbstractHttpControllerTestCase;
use Laminas\Session\Container as SessionContainer;
use TwoFactorAuth\Controller\LoginController;

/**
 * Tests the redirection after login to the url stored in session, for example
 * by another module.
 */
class LoginControllerTest extends AbstractHttpControllerTestCase
{
    /**
     * Get the controller with the request of a dispatch, as admin.
     */
    protected function controller(): LoginController
    {
        $this->dispatch('/admin');
        $controller = $this->getApplication()->getServiceManager()
            ->get('ControllerManager')->get('Omeka\Controller\Login');
        $this->assertInstanceOf(LoginController::class, $controller);
        $controller->setEvent($this->getApplication()->getMvcEvent());
        return $controller;
    }

    protected function setSessionRedirectUrl(?string $redirectUrl): void
    {
        $session = SessionContainer::getDefaultManager()->getStorage();
        $redirectUrl === null
            ? $session->offsetUnset('redirect_url')
            : $session->offsetSet('redirect_url', $redirectUrl);
    }

    public function testLoggedUserIsRedirectedToTheStoredUrl(): void
    {
        $controller = $this->controller();
        $this->setSessionRedirectUrl('/s/site-test');
        $response = $controller->loginAction();
        $this->assertSame('/s/site-test', $response->getHeaders()->get('Location')->getFieldValue());
    }

    public function testLoggedUserIsRedirectedToAdminWithoutStoredUrl(): void
    {
        $controller = $this->controller();
        $this->setSessionRedirectUrl(null);
        $response = $controller->loginAction();
        $this->assertStringEndsWith('/admin', $response->getHeaders()->get('Location')->getFieldValue());
    }

    public function testStoredUrlIsRestoredAfterRenewedSession(): void
    {
        $controller = $this->controller();
        $this->setSessionRedirectUrl(null);
        $method = new \ReflectionMethod($controller, 'keepSessionRedirectUrl');
        $method->setAccessible(true);
        $method->invoke($controller, '/s/site-test');
        $this->assertSame('/s/site-test', SessionContainer::getDefaultManager()->getStorage()->offsetGet('redirect_url'));
    }
}
