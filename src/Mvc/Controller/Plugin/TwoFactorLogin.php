<?php declare(strict_types=1);

namespace TwoFactorAuth\Mvc\Controller\Plugin;

use Common\Mvc\Controller\Plugin\SendEmail;
use Doctrine\ORM\EntityManager;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\AuthenticationService;
use Laminas\EventManager\EventManager;
use Laminas\Http\Request;
use Laminas\Log\Logger;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use Laminas\Mvc\Controller\Plugin\Url;
use Laminas\Session\Container as SessionContainer;
use Omeka\Api\Representation\SiteRepresentation;
use Omeka\Entity\User;
use Omeka\Mvc\Controller\Plugin\Messenger;
use Omeka\Mvc\Controller\Plugin\Translate;
use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;
use TwoFactorAuth\Entity\Token;

class TwoFactorLogin extends AbstractPlugin
{
    /**
     * Maximum number of invalid PIN attempts before the 2FA session is
     * invalidated and the user must restart the login flow.
     */
    const MAX_ATTEMPTS = 5;

    /**
     * Minimum delay in seconds between two "resend code" requests.
     */
    const RESEND_MIN_INTERVAL = 30;

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
     * @var Messenger
     */
    protected $messenger;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var SendEmail
     */
    protected $sendEmail;

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
        Messenger $messenger,
        Request $request,
        SendEmail $sendEmail,
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
        $this->messenger = $messenger;
        $this->request = $request;
        $this->sendEmail = $sendEmail;
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
        // Create a new session, avoiding the warning in case of error.
        // Avoid warning: session_regenerate_id(): Session object destruction
        // failed when session save handler has issues.
        // See /vendor/laminas/laminas-session/src/SessionManager.php on line 337.
        $sessionManager = SessionContainer::getDefaultManager();
        @$sessionManager->regenerateId();
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
            $this->logger->warn(
                '[TwoFactorAuth] Login attempt on unknown identity: {email}.', // @translate
                ['email' => $email]
            );
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
        // Create a new session, avoiding the warning in case of error.
        // Avoid warning: session_regenerate_id(): Session object destruction
        // failed when session save handler has issues.
        // See /vendor/laminas/laminas-session/src/SessionManager.php on line 337.
        $sessionManager = SessionContainer::getDefaultManager();
        @$sessionManager->regenerateId();

        $session = $sessionManager->getStorage();
        $session->offsetSet('tfa_user_email', $user->getEmail());
        // Reset rate-limit counters: a fresh 2FA session starts with a full set
        // of attempts and the resend throttle window restarts.
        $session->offsetUnset('tfa_attempts');
        $session->offsetUnset('tfa_last_sent');
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

        // Create a new session, avoiding the warning in case of error.
        // Avoid warning: session_regenerate_id(): Session object destruction
        // failed when session save handler has issues.
        // See /vendor/laminas/laminas-session/src/SessionManager.php on line 337.
        $sessionManager = SessionContainer::getDefaultManager();
        @$sessionManager->regenerateId();
        $session = $sessionManager->getStorage();
        $userEmail = $session->offsetGet('tfa_user_email');
        if (!$userEmail) {
            $this->messenger->addError(
                'An error occurred. Retry to log in.' // @translate
            );
            return null;
        }

        // Block brute force: cap failed attempts per 2FA session. When the cap
        // is reached, drop the 2FA session so the user must re-authenticate
        // from step 1 (new token required).
        $attempts = (int) $session->offsetGet('tfa_attempts');
        if ($attempts >= self::MAX_ATTEMPTS) {
            $session->offsetUnset('tfa_user_email');
            $session->offsetUnset('tfa_attempts');
            $session->offsetUnset('tfa_last_sent');
            $user = $this->userFromEmail($userEmail);
            if ($user) {
                /** @var \TwoFactorAuth\Authentication\Adapter\TokenAdapter $adapter */
                $adapter = $this->authenticationService->getAdapter();
                $adapter->cleanTokens($user);
            }
            $this->logger->warn(
                '[TwoFactorAuth] Too many invalid codes for {email}. 2FA session invalidated.', // @translate
                ['email' => $userEmail]
            );
            $this->messenger->addError(
                'Too many invalid codes. Retry to log in.' // @translate
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
            $session->offsetUnset('tfa_attempts');
            $session->offsetUnset('tfa_last_sent');
            $this->messenger->clear();
            $this->messenger->addSuccess('Successfully logged in'); // @translate
            $this->eventManager->trigger('user.login', $this->authenticationService->getIdentity());
            return true;
        }

        // Slow down the process to mitigate online brute force attempts.
        sleep(3);
        $session->offsetSet('tfa_attempts', $attempts + 1);
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

        $subject = $this->settings->get('twofactorauth_message_subject')
            ?: $this->translate->__invoke($this->configModule['config']['twofactorauth_message_subject']);
        $body = $this->settings->get('twofactorauth_message_body')
            ?: $this->translate->__invoke($this->configModule['config']['twofactorauth_message_body']);

        $mainTitle = $this->settings->get('installation_title', 'Omeka S');
        $mainUrl = $this->url->fromRoute('top', [], ['force_canonical' => true]);
        $siteTitle = $this->site ? $this->site->title() : $mainTitle;
        $siteUrl = $this->site ? $this->site->siteUrl(null, true) : $mainUrl;

        $map = [
            'main_title' => $mainTitle,
            'main_url' => $mainUrl,
            'site_title' => $siteTitle,
            'site_url' => $siteUrl,
            'email' => $user->getEmail(),
            'name' => $user->getName(),
            'user_email' => $user->getEmail(),
            'user_name' => $user->getName(),
            'token' => $token->getCode(),
            'code' => $token->getCode(),
        ];
        $replace = [];
        foreach ($map as $k => $v) {
            $replace['{' . $k . '}'] = $v;
        }
        $subject = strtr($subject, $replace);
        $body = strtr($body, $replace);

        $to = [$user->getEmail() => $user->getName()];

        $result = ($this->sendEmail)($body, $subject, $to);
        if (!$result) {
            $this->logger->err(
                'Error when sending 2FA token email to {email}.', // @translate
                ['email' => $user->getEmail()]
            );
        }
        return $result;
    }

    public function resendToken(): bool
    {
        $sessionManager = SessionContainer::getDefaultManager();
        $session = $sessionManager->getStorage();
        $userEmail = $session->offsetGet('tfa_user_email');
        if (!$userEmail) {
            return false;
        }

        // Throttle resend requests to mitigate email spam and token enumeration
        // by repeated regeneration.
        $now = time();
        $lastSent = (int) $session->offsetGet('tfa_last_sent');
        if ($lastSent && ($now - $lastSent) < self::RESEND_MIN_INTERVAL) {
            return false;
        }

        $user = $this->userFromEmail($userEmail);
        if (!$user) {
            return false;
        }

        // Don't log again: the possible issue with email is already logged.
        $token = $this->prepareToken($user);
        $result = $this->sendToken($token);
        if ($result) {
            $session->offsetSet('tfa_last_sent', $now);
        }
        return $result;
    }

}
