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
}
