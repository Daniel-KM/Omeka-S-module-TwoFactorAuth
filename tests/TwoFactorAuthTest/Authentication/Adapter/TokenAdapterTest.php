<?php declare(strict_types=1);

namespace TwoFactorAuthTest\Authentication\Adapter;

use CommonTest\AbstractHttpControllerTestCase;
use TwoFactorAuth\Authentication\Adapter\TokenAdapter;

/**
 * Other modules authenticate with the password through the service directly.
 */
class TokenAdapterTest extends AbstractHttpControllerTestCase
{
    protected function adapter(): TokenAdapter
    {
        $this->dispatch('/login');
        $adapter = $this->getApplication()->getServiceManager()
            ->get('Omeka\AuthenticationService')->getAdapter();
        $this->assertInstanceOf(TokenAdapter::class, $adapter);
        return $adapter;
    }

    public function testWrongPasswordIsRefusedWithoutSecondFactor(): void
    {
        $result = $this->adapter()
            ->setIdentity('admin@example.com')
            ->setCredential('wrong password')
            ->authenticate();
        $this->assertFalse($result->isValid());
    }

    public function testPasswordIsAcceptedWithoutSecondFactor(): void
    {
        $result = $this->adapter()
            ->setIdentity('admin@example.com')
            ->setCredential('root')
            ->authenticate();
        $this->assertTrue($result->isValid());
    }

    public function testCodeIsAcceptedOnlyInTheSecondStep(): void
    {
        $adapter = $this->adapter();
        $services = $this->getApplication()->getServiceManager();
        $user = $adapter->getUserRepository()->findOneBy(['email' => 'admin@example.com']);
        $userSettings = $services->get('Omeka\Settings\User');
        $userSettings->set('twofactorauth_active', true, $user->getId());
        try {
            $code = (string) $adapter->createToken($user)->getCode();
            $this->assertSame(6, strlen($code));

            // Another module sends the code as a password.
            $result = $adapter->setIdentity('admin@example.com')->setCredential($code)->authenticate();
            $this->assertFalse($result->isValid());

            // The password alone is not enough.
            $result = $adapter->setIdentity('admin@example.com')->setCredential('root')->authenticate();
            $this->assertFalse($result->isValid());

            $result = $adapter->setSecondStep(true)->setIdentity('admin@example.com')->setCredential($code)->authenticate();
            $this->assertTrue($result->isValid());
        } finally {
            $userSettings->set('twofactorauth_active', false, $user->getId());
            $adapter->cleanTokens($user);
        }
    }
}
