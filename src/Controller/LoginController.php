<?php declare(strict_types=1);

namespace TwoFactorAuth\Controller;

use Doctrine\ORM\EntityManager;
use Omeka\Form\LoginForm;
use Laminas\Authentication\AuthenticationService;
use Laminas\Mail\Address;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container;
use Laminas\View\Model\ViewModel;
use Omeka\Controller\LoginController as OmekaLoginController;
use Omeka\Entity\User;
use ReflectionObject;
use TwoFactorAuth\Form\TokenForm;

/**
 * @todo Extend the omeka login controller is probably useless.
 */
class LoginController extends OmekaLoginController
{
    /**
     * @var \Omeka\Controller\LoginController|\Guest\Controller\Site\AnonymousController|\Lockout\Controller\LoginController|\UserNames\Controller\LoginController
     */
    protected $realLoginController;

    /**
     * @var array
     */
    protected $configModule;

    public function __construct(
        AbstractActionController $realLoginController,
        AuthenticationService $auth,
        EntityManager $entityManager,
        array $configModule
    ) {
        $this->realLoginController = $realLoginController;
        $this->auth = $auth;
        $this->entityManager = $entityManager;
        $this->configModule = $configModule;
    }

    public function loginAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')
                ? $this->redirect()->toRoute('admin')
                : $this->redirect()->toRoute('top');
        }

        // The TokenForm returns to the login action, so check it when needed.
        /** @var \Laminas\Http\PhpEnvironment\Request $request */
        $request = $this->getRequest();
        if ($request->isPost() && $request->getPost('submit_token')) {
            return $this->loginTokenAction();
        }

        $form = $this->getForm(LoginForm::class);

        if ($this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form->setData($data);
            if ($form->isValid()) {
                // Don't regenerate session early: it must be once.
                $validatedData = $form->getData();

                /**
                 * @var \TwoFactorAuth\Authentication\Adapter\TokenAdapter $adapter
                 * @var \Omeka\Entity\User $user
                 */

                // Check if the user require a second factor.
                $adapter = $this->auth->getAdapter();
                $userRepository = $this->entityManager->getRepository(User::class);
                $user = $userRepository->findOneBy(['email' => $validatedData['email']]);
                // Manage delegated modules (Omeka, Guest, Lockout, UserNames).
                // Normally, the method always exists.
                $realAdapter = method_exists($adapter, 'getRealAdapter')
                    ? $adapter->getRealAdapter()
                    : $adapter;
                // Manage module UserNames.
                if (!$user && $realAdapter instanceof \UserNames\Authentication\Adapter\PasswordAdapter) {
                    $userName = $realAdapter->getUserNameRepository()->findOneBy(['userName' => $validatedData['email']]);
                    if ($userName) {
                        $user = $userRepository->findOneBy(['id' => $userName->getUser()]);
                    }
                }
                $requireSecondFactor = $user
                    ? $adapter->requireSecondFactor($user)
                    : (bool) $this->settings()->get('twofactorauth_force_2fa');

                if (!$requireSecondFactor) {
                    // This is simpler to use real login controller even if
                    // there is some repetitions of form checks.
                    $this->auth->setAdapter($realAdapter);
                    // Services must be injected in the real login controller.
                    // All methods are not fluid.
                    $this->realLoginController
                        ->setEventManager($this->getEventManager())
                        ->setPluginManager($this->getPluginManager())
                        ->setEvent($this->getEvent());
                    // There is no method setRequest() in controller, but the
                    // current request is required to check the post, so copy
                    // it manually.
                    $reflectionRealLoginController = new ReflectionObject($this->realLoginController);
                    $prop = $reflectionRealLoginController->getProperty('request');
                    $prop->setAccessible(true);
                    $prop->setValue($this->realLoginController, $this->getRequest());
                    $prop->setAccessible(false);
                    return $this->realLoginController->loginAction();
                }

                $sessionManager = Container::getDefaultManager();
                $sessionManager->regenerateId();

                // Check for the first step, and go to second step when success.
                // So don't use authentication service, but the real adapter.
                $result = $realAdapter
                    ->setIdentity($validatedData['email'])
                    ->setCredential($validatedData['password'])
                    ->authenticate();
                if ($result->isValid()) {
                    // Create token and send email.
                    $token = $adapter
                        ->cleanTokens($user)
                        ->createToken($user);
                    $emailParams = [
                        'subject' => $this->settings()->get('twofactorauth_message_subject')
                            ?: $this->translate($this->configModule['config']['twofactorauth_message_subject']),
                        'body' => $this->settings()->get('twofactorauth_message_body')
                            ?: $this->translate($this->configModule['config']['twofactorauth_message_body']),
                        'to' => [
                            $user->getEmail() => $user->getName(),
                        ],
                        'map' => [
                            'user_email' => $user->getEmail(),
                            'user_name' => $user->getName(),
                            'token' => $token->getToken(),
                        ],
                    ];
                    $result = $this->sendEmail($emailParams);
                    if (!$result) {
                        $this->messenger()->addError('An error occurred when the token was sent by email. Try again later.'); // @translate
                        $this->logger()->err('[TwoFactorAuth] An error occurred when the token was sent by email.'); // @translate
                        return $this->redirect()->toRoute('login');
                    }

                    // Prepare the second step.
                    $session = $sessionManager->getStorage();
                    $session->offsetSet('tfa_user_email', $user->getEmail());
                    $this->getRequest()->setMetadata('first', true);
                    $this->messenger()->addSuccess(
                        'Fill the second form with the code received by email to log in' // @translate
                    );
                    return $this->forward()->dispatch('Omeka\Controller\Login', [
                        'controller' => 'Omeka\Controller\Login',
                        'action' => 'login-token',
                    ]);
                } else {
                    $this->messenger()->addError(
                        'Email or password is invalid' // @translate
                    );
                }
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        return new ViewModel([
            'form' => $form,
        ]);
    }

    public function loginTokenAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')
                ? $this->redirect()->toRoute('admin')
                : $this->redirect()->toRoute('top');
        }

        $form = $this->getForm(TokenForm::class);

        $isFirst = (bool) $this->getRequest()->getMetadata('first');

        if (!$isFirst && $this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form->setData($data);
            if ($form->isValid()) {
                /**
                 * @var \TwoFactorAuth\Authentication\Adapter\TokenAdapter $adapter
                 * @var \Omeka\Entity\User $user
                 */
                $sessionManager = Container::getDefaultManager();
                $sessionManager->regenerateId();
                $session = $sessionManager->getStorage();
                $userEmail = $session->offsetGet('tfa_user_email');
                if (!$userEmail) {
                    $this->messenger()->addError(
                        'An error occurred. Retry to log in.' // @translate
                    );
                    return $this->redirect()->toRoute('login');
                }

                $validatedData = $form->getData();

                $adapter = $this->auth->getAdapter();
                $adapter
                    ->setIdentity($userEmail)
                    // In second step, the 2fa token is the credential.
                    ->setCredential($validatedData['token_email'] ?? null);

                // Here, use the authentication service.
                $result = $this->auth->authenticate();
                if ($result->isValid()) {
                    $this->messenger()->addSuccess('Successfully logged in'); // @translate
                    $eventManager = $this->getEventManager();
                    $eventManager->trigger('user.login', $this->auth->getIdentity());
                    $session = $sessionManager->getStorage();
                    if ($redirectUrl = $session->offsetGet('redirect_url')) {
                        return $this->redirect()->toUrl($redirectUrl);
                    }
                    return $this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')
                        ? $this->redirect()->toRoute('admin')
                        : $this->redirect()->toRoute('top');
                } else {
                    $this->messenger()->addError('The token is invalid.'); // @translate
                }
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        return new ViewModel([
            'form' => $form,
        ]);
    }

    /**
     * Send an email.
     *
     * @param array $params The params are already checked (from, to, subject,
     * body).
     * @see \Omeka\Stdlib\Mailer
     */
    protected function sendEmail(array $params): bool
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
            $this->logger()->err(
                'The message has no subject, content or recipient.' // @translate
            );
            return false;
        }

        $mainTitle = $this->settings()->get('installation_title', 'Omeka S');
        $mainUrl = $this->url()->fromRoute('top', [], ['force_canonical' => true]);
        /** @var \Omeka\Api\Representation\SiteRepresentation $site */
        $site = $this->currentSite();
        $siteTitle = $site ? $site->title() : $mainTitle;
        $siteUrl = $site ? $site->siteUrl(null, true) : $mainUrl;

        $userEmail = !empty($params['user_email'])
            ? $params['user_email']
            : (!empty($params['email'])
                ? $params['email']
                : (!empty($params['user']) ? $user->getEmail() : ''));
        $userName = !empty($params['user_name'])
            ? $params['user_name']
            : (!empty($params['name'])
                ? $params['name']
                : (!empty($params['user']) ? $user->getName() : ''));

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

        /** @var \Omeka\Stdlib\Mailer $mailer */
        $mailer = $this->mailer();

        $getAddress = fn ($email, $name) => new Address(is_string($email) && strpos($email, '@') ? $email : $name, $name);

        $message = $mailer->createMessage();
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
            $mailer->send($message);
            return true;
        } catch (\Exception $e) {
            $this->logger()->err(
                "Error when sending email. Arguments:\n{json}", // @translate
                ['json' => json_encode($params, 448)]
            );
            return false;
        }
    }
}
