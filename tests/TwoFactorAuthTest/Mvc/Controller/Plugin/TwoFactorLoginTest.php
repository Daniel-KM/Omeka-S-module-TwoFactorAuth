<?php declare(strict_types=1);

namespace TwoFactorAuthTest\Mvc\Controller\Plugin;

use Common\Mvc\Controller\Plugin\SendEmail;
use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\EventManager\EventManager;
use Laminas\Http\Request;
use Laminas\Log\Logger;
use Laminas\Mvc\Controller\Plugin\Url;
use Omeka\Entity\User;
use Omeka\Mvc\Controller\Plugin\Messenger;
use Omeka\Mvc\Controller\Plugin\Translate;
use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;
use PHPUnit\Framework\TestCase;
use TwoFactorAuth\Entity\Token;
use TwoFactorAuth\Mvc\Controller\Plugin\TwoFactorLogin;

class TwoFactorLoginTest extends TestCase
{
    protected function makePlugin(SendEmail $sendEmail, array $settingsMap = [], array $configModule = []): TwoFactorLogin
    {
        $settings = $this->createMock(Settings::class);
        $settings->method('get')->willReturnCallback(
            fn ($key, $default = null) => $settingsMap[$key] ?? $default
        );

        $url = $this->createMock(Url::class);
        $url->method('fromRoute')->willReturn('https://example.org/');

        $translate = $this->createMock(Translate::class);
        $translate->method('__invoke')->willReturnArgument(0);

        $configModule += [
            'config' => [
                'twofactorauth_message_subject' => '[{site_title}] {token}',
                'twofactorauth_message_body' => "Hi {user_name} ({email}), code {token} for {site_title}.",
            ],
        ];

        return new TwoFactorLogin(
            $this->createMock(AuthenticationService::class),
            $this->createMock(EntityManager::class),
            $this->createMock(EventManager::class),
            $this->createMock(Logger::class),
            $this->createMock(Messenger::class),
            $this->createMock(Request::class),
            $sendEmail,
            $settings,
            $translate,
            $url,
            $this->createMock(UserSettings::class),
            null,
            $configModule,
            false
        );
    }

    protected function makeToken(string $email, string $name, int $code): Token
    {
        $user = new User();
        $user->setEmail($email);
        $user->setName($name);
        $token = new Token();
        $token->setUser($user);
        $token->setCode($code);
        return $token;
    }

    public function testSendTokenReplacesAllPlaceholders(): void
    {
        $captured = (object) ['body' => null, 'subject' => null, 'to' => null];
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturnCallback(
            function ($body, $subject, $to) use ($captured) {
                $captured->body = $body;
                $captured->subject = $subject;
                $captured->to = $to;
                return true;
            }
        );

        $plugin = $this->makePlugin($sendEmail, [
            'installation_title' => 'My Omeka',
        ]);
        $token = $this->makeToken('alice@example.org', 'Alice', 123456);

        $this->assertTrue($plugin->sendToken($token));
        $this->assertSame('[My Omeka] 123456', $captured->subject);
        $this->assertSame(
            '<div>Hi Alice (alice@example.org), code 123456 for My Omeka.</div>',
            $captured->body
        );
        $this->assertSame(['alice@example.org' => 'Alice'], $captured->to);
    }

    public function testSendTokenUsesCustomMessageFromSettings(): void
    {
        $captured = (object) ['body' => null, 'subject' => null];
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturnCallback(
            function ($body, $subject) use ($captured) {
                $captured->body = $body;
                $captured->subject = $subject;
                return true;
            }
        );

        $plugin = $this->makePlugin($sendEmail, [
            'installation_title' => 'Site',
            'twofactorauth_message_subject' => 'Code {code}',
            'twofactorauth_message_body' => 'User {user_email} code {code}',
        ]);
        $token = $this->makeToken('bob@example.org', 'Bob', 42);

        $plugin->sendToken($token);
        $this->assertSame('Code 42', $captured->subject);
        $this->assertSame('<div>User bob@example.org code 42</div>', $captured->body);
    }

    public function testSendTokenReturnsFalseWhenEmailFails(): void
    {
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturn(false);

        $plugin = $this->makePlugin($sendEmail);
        $token = $this->makeToken('x@example.org', 'X', 1);

        $this->assertFalse($plugin->sendToken($token));
    }

    public function testPlaceholderAliasesCoexist(): void
    {
        $captured = (object) ['body' => null];
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturnCallback(
            function ($body) use ($captured) {
                $captured->body = $body;
                return true;
            }
        );

        $plugin = $this->makePlugin($sendEmail, [
            'twofactorauth_message_body' => '{email}|{user_email}|{name}|{user_name}|{token}|{code}',
        ]);
        $token = $this->makeToken('c@example.org', 'Carol', 9);

        $plugin->sendToken($token);
        $this->assertSame(
            '<div>c@example.org|c@example.org|Carol|Carol|9|9</div>',
            $captured->body
        );
    }

    public function testSendTokenWrapsBodyAsHtml(): void
    {
        $captured = (object) ['body' => null];
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturnCallback(
            function ($body) use ($captured) {
                $captured->body = $body;
                return true;
            }
        );
        $token = $this->makeToken('d@example.org', 'Dan', 7);

        // A plain text body keeps its line breaks.
        $plugin = $this->makePlugin($sendEmail, [
            'twofactorauth_message_body' => "Hi {name},\nCode {code}",
        ]);
        $plugin->sendToken($token);
        $this->assertSame("<div>Hi Dan,<br />\nCode 7</div>", $captured->body);

        // A html body, even starting with a text, is kept as is.
        $plugin = $this->makePlugin($sendEmail, [
            'twofactorauth_message_body' => "Hi {name},<br>\nCode <b>{code}</b>",
        ]);
        $plugin->sendToken($token);
        $this->assertSame("<div>Hi Dan,<br>\nCode <b>7</b></div>", $captured->body);
    }

    public function testSendTokenEscapesValuesInHtmlBodyOnly(): void
    {
        $captured = (object) ['body' => null, 'subject' => null];
        $sendEmail = $this->getMockBuilder(SendEmail::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__invoke'])
            ->getMock();
        $sendEmail->method('__invoke')->willReturnCallback(
            function ($body, $subject) use ($captured) {
                $captured->body = $body;
                $captured->subject = $subject;
                return true;
            }
        );
        $token = $this->makeToken('e@example.org', 'Tom & <Jerry>', 8);

        $plugin = $this->makePlugin($sendEmail, [
            'twofactorauth_message_subject' => 'Code for {name}',
            'twofactorauth_message_body' => 'Hi {name}, code {code}',
        ]);
        $plugin->sendToken($token);
        $this->assertSame('<div>Hi Tom &amp; &lt;Jerry&gt;, code 8</div>', $captured->body);
        $this->assertSame('Code for Tom & <Jerry>', $captured->subject);
    }
}
