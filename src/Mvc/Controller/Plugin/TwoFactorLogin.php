<?php declare(strict_types=1);

namespace TwoFactorAuth\Mvc\Controller\Plugin;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\AuthenticationService;
use Laminas\EventManager\EventManager;
use Laminas\Http\Request;
use Laminas\Log\Logger;
use Laminas\Mail\Address;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use Laminas\Mvc\Controller\Plugin\Url;
use Laminas\Session\Container as SessionContainer;
use Omeka\Api\Representation\SiteRepresentation;
use Omeka\Entity\User;
use Omeka\Mvc\Controller\Plugin\Messenger;
use Omeka\Mvc\Controller\Plugin\Translate;
use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;
use Omeka\Stdlib\Mailer;
use TwoFactorAuth\Entity\Token;

class TwoFactorLogin extends AbstractPlugin
{
    /**
     * @var AuthenticationService
     */
    protected $authenticationService;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var EventManager
     */
    protected $eventManager;

    /**
     * @var Logger
     */
    protected $logger;

    /**
     * @var Mailer
     */
    protected $mailer;

    /**
     * @var Messenger
     */
    protected $messenger;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var Settings
     */
    protected $settings;

    /**
     * @var Translate
     */
    protected $translate;

    /**
     * @var Url
     */
    protected $url;

    /**
     * @var UserSettings
     */
    protected $userSettings;

    /**
     * @var SiteRepresentation|null
     */
    protected $site;

    /**
     * @var array
     */
    protected $configModule;

    /**
     * @var bool
     */
    protected $hasModuleUserNames;

    public function __construct(
        AuthenticationService $authenticationService,
        EntityManager $entityManager,
        EventManager $eventManager,
        Logger $logger,
        Mailer $mailer,
        Messenger $messenger,
        Request $request,
        Settings $settings,
        Translate $translate,
        Url $url,
        UserSettings $userSettings,
        ?SiteRepresentation $site,
        array $configModule,
        bool $hasModuleUserNames
    ) {
        $this->authenticationService = $authenticationService;
        $this->entityManager = $entityManager;
        $this->eventManager = $eventManager;
        $this->logger = $logger;
        $this->mailer = $mailer;
        $this->messenger = $messenger;
        $this->request = $request;
        $this->settings = $settings;
        $this->translate = $translate;
        $this->url = $url;
        $this->userSettings = $userSettings;
        $this->site = $site;
        $this->configModule = $configModule;
        $this->hasModuleUserNames = $hasModuleUserNames;
    }

    public function __invoke(): self
    {
        return $this;
    }

    public function userFromEmail(string $email): ?User
    {
        $userRepository = $this->entityManager->getRepository(User::class);
        $user = $userRepository->findOneBy(['email' => $email]);
        $realAdapter = $this->realAuthenticationAdapter();
        if (!$user && $realAdapter instanceof \UserNames\Authentication\Adapter\PasswordAdapter) {
            $userName = $realAdapter->getUserNameRepository()->findOneBy(['userName' => $email]);
            if ($userName) {
                $user = $userRepository->findOneBy(['id' => $userName->getUser()]);
            }
        }
        return $user;
    }

    /**
     * Get the real authentication adapter.
     *
     * Manage delegated modules (Omeka, Guest, Lockout, UserNames).
     */
    public function realAuthenticationAdapter(): AdapterInterface
    {
        // Normally, the method always exists when the module is enabled.
        $adapter = $this->authenticationService->getAdapter();
        return method_exists($adapter, 'getRealAdapter')
            ? $adapter->getRealAdapter()
            : $adapter;
    }

    /**
     * Check if the user require a second factor.
     *
     * @param User|string|null $userOrEmail
     */
    public function requireSecondFactor($userOrEmail): bool
    {
        if ($this->settings->get('twofactorauth_force_2fa')) {
            return true;
        }

        if (!$userOrEmail) {
            return false;
        }

        $user = is_object($userOrEmail)
            ? $userOrEmail
            : $this->userFromEmail($userOrEmail);

        return $user
            ? (bool) $this->userSettings->get('twofactorauth_active', false, $user->getId())
            : false;
    }

    public function processLogin(string $email, string $password): bool
    {
        $sessionManager = SessionContainer::getDefaultManager();
        $sessionManager->regenerateId();
        $adapter = $this->authenticationService->getAdapter();
        $adapter->setIdentity($email);
        $adapter->setCredential($password);
        $result = $this->authenticationService->authenticate();
        if (!$result->isValid()) {
            return false;
        }
        $this->messenger->clear();
        $this->messenger->addSuccess('Successfully logged in'); // @translate
        $this->eventManager->trigger('user.login', $this->authenticationService->getIdentity());
        return true;
    }

    public function validateLoginStep1(string $email, string $password): bool
    {
        $user = $this->userFromEmail($email);
        if (!$user) {
            sleep(3);
            return false;
        }

        // Check for the first step, and go to second step when success.
        // So don't use authentication service, but the real adapter.
        $realAdapter = $this->realAuthenticationAdapter();
        $result = $realAdapter
            ->setIdentity($email)
            ->setCredential($password)
            ->authenticate();
        if (!$result->isValid()) {
            sleep(3);
            $this->messenger->addError(
                'Email or password is invalid' // @translate
            );
            return false;
        }

        return true;
    }

    /**
     * Prepare a token and send an email for the specified user.
     *
     * No check is done about first step.
     */
    public function prepareLoginStep2(User $user): bool
    {
        $token = $this->prepareToken($user);
        $result = $this->sendToken($token);
        if (!$result) {
            $this->messenger->addError(
                'An error occurred when the code was sent by email. Try again later.' // @translate
            );
            $this->logger->err(
                '[TwoFactorAuth] An error occurred when the code was sent by email.' // @translate
            );
            return false;
        }

        // Prepare the second step.
        $sessionManager = SessionContainer::getDefaultManager();
        $sessionManager->regenerateId();

        $session = $sessionManager->getStorage();
        $session->offsetSet('tfa_user_email', $user->getEmail());
        $this->request->setMetadata('first', true);
        $this->messenger->addSuccess(
            'Fill the second form with the code received by email to log in' // @translate
        );

        return true;
    }

    /**
     * Validate a token for the stored user.
     *
     * @param string $code
     * @return bool|null Return null when an internal error occurred, else a
     * bool if the code is good or not.
     */
    public function validateLoginStep2(?string $code): ?bool
    {
        if (!$code) {
            $this->messenger->addError(
                'The code is missing.' // @translate
            );
            return false;
        }

        $sessionManager = SessionContainer::getDefaultManager();
        $sessionManager->regenerateId();
        $session = $sessionManager->getStorage();
        $userEmail = $session->offsetGet('tfa_user_email');
        if (!$userEmail) {
            $this->messenger->addError(
                'An error occurred. Retry to log in.' // @translate
            );
            return null;
        }

        /** @var \TwoFactorAuth\Authentication\Adapter\TokenAdapter $adapter */
        $adapter = $this->authenticationService->getAdapter();
        $adapter
            ->setIdentity($userEmail)
            // In second step, the 2fa token is the credential.
            ->setCredential($code);

        // Here, use the authentication service.
        $result = $this->authenticationService->authenticate();
        if ($result->isValid()) {
            $this->messenger->clear();
            $this->messenger->addSuccess('Successfully logged in'); // @translate
            $this->eventManager->trigger('user.login', $this->authenticationService->getIdentity());
            return true;
        }

        // TODO Add a counter to avoid brute-force attack. For now, a sleep is enough.
        // Slow down the process to avoid brute force.
        sleep(3);
        $this->messenger->addError('Invalid code'); // @translate
        return false;
    }

    public function prepareToken(User $user): Token
    {
        // Create token and send email.
        /** @var \TwoFactorAuth\Authentication\Adapter\TokenAdapter $adapter */
        $adapter = $this->authenticationService->getAdapter();
        return $adapter
            ->cleanTokens($user)
            ->createToken($user);
    }

    public function sendToken(Token $token): bool
    {
        $user = $token->getUser();

        $emailParams = [
            'subject' => $this->settings->get('twofactorauth_message_subject')
                ?: $this->translate->__invoke($this->configModule['config']['twofactorauth_message_subject']),
            'body' => $this->settings->get('twofactorauth_message_body')
                ?: $this->translate->__invoke($this->configModule['config']['twofactorauth_message_body']),
            'to' => [
                $user->getEmail() => $user->getName(),
            ],
            'map' => [
                'user_email' => $user->getEmail(),
                'user_name' => $user->getName(),
                'token' => $token->getCode(),
                'code' => $token->getCode(),
            ],
        ];

        return $this->sendEmail($emailParams);
    }

    public function resendToken(): bool
    {
        $sessionManager = SessionContainer::getDefaultManager();
        $session = $sessionManager->getStorage();
        $userEmail = $session->offsetGet('tfa_user_email');
        if (!$userEmail) {
            return false;
        }

        $user = $this->userFromEmail($userEmail);
        if (!$user) {
            return false;
        }

        // Don't log again: the possible issue with email is already logged.
        $token = $this->prepareToken($user);
        return $this->sendToken($token);
    }

    /**
     * Send an email.
     *
     * @param array $params Params are already checked (from, to, subject, body).
     * @see \Omeka\Stdlib\Mailer
     */
    public function sendEmail(array $params): bool
    {
        $defaultParams = [
            'subject' => null,
            'body' => null,
            'from' => [],
            'to' => [],
            'cc' => [],
            'bcc' => [],
            'reply-to' => [],
            'map' => [],
        ];
        $params += $defaultParams;

        if (empty($params['to']) || empty($params['subject']) || empty($params['body'])) {
            $this->logger->err(
                'The message has no subject, content or recipient.' // @translate
            );
            return false;
        }

        $mainTitle = $this->settings->get('installation_title', 'Omeka S');
        $mainUrl = $this->url->fromRoute('top', [], ['force_canonical' => true]);
        $siteTitle = $this->site ? $this->site->title() : $mainTitle;
        $siteUrl = $this->site ? $this->site->siteUrl(null, true) : $mainUrl;

        $userEmail = !empty($params['user_email'])
            ? $params['user_email']
            : (!empty($params['email'])
                ? $params['email']
                : (!empty($params['user']) ? $params['user']->getEmail() : ''));
        $userName = !empty($params['user_name'])
            ? $params['user_name']
            : (!empty($params['name'])
                ? $params['name']
                : (!empty($params['user']) ? $params['user']->getName() : ''));

        $map = $params['map'] + [
            'main_title' => $mainTitle,
            'main_url' => $mainUrl,
            'site_title' => $siteTitle,
            'site_url' => $siteUrl,
            'user_email' => $userEmail,
            'user_name' => $userName,
        ];
        $subject = str_replace(array_map(fn ($v) => '{' . $v . '}', array_keys($map)), array_values($map), $params['subject']);
        $body = str_replace(array_map(fn ($v) => '{' . $v . '}', array_keys($map)), array_values($map), $params['body']);

        $getAddress = fn ($email, $name) => new Address(is_string($email) && strpos($email, '@') ? $email : $name, $name);

        $message = $this->mailer->createMessage();
        $message
            ->setSubject($subject)
            ->setBody($body);
        if (!empty($params['from'])) {
            $from = is_array($params['from']) ? $params['from'] : [$params['from']];
            $message->setFrom($getAddress(key($from), reset($from)));
        }
        $to = is_array($params['to']) ? $params['to'] : [$params['to']];
        foreach ($to as $email => $name) {
            $message->addTo($getAddress($email, $name));
        }
        $cc = is_array($params['cc']) ? $params['cc'] : [$params['cc']];
        foreach ($cc as $email => $name) {
            $message->addCc($getAddress($email, $name));
        }
        $bcc = is_array($params['bcc']) ? $params['bcc'] : [$params['bcc']];
        foreach ($bcc as $email => $name) {
            $message->addBcc($getAddress($email, $name));
        }
        $replyTo = is_array($params['reply-to']) ? $params['reply-to'] : [$params['reply-to']];
        foreach ($replyTo as $email => $name) {
            $message->addReplyTo($getAddress($email, $name));
        }
        try {
            $this->mailer->send($message);
            return true;
        } catch (\Exception $e) {
            $this->logger->err(
                "Error when sending email. Arguments:\n{json}", // @translate
                ['json' => json_encode($params, 448)]
            );
            return false;
        }
    }
}
