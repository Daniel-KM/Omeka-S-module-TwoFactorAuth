<?php declare(strict_types=1);

namespace TwoFactorAuth\Controller;

use Doctrine\ORM\EntityManager;
use Omeka\Form\LoginForm;
use Laminas\Authentication\AuthenticationService;
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

    public function __construct(
        AbstractActionController $realLoginController,
        EntityManager $entityManager,
        AuthenticationService $auth
    ) {
        $this->realLoginController = $realLoginController;
        $this->entityManager = $entityManager;
        $this->auth = $auth;
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
                    : false;

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
                    $adapter
                        ->cleanTokens($user)
                        ->createToken($user);
                    $this->messenger()->addSuccess(
                        'Fill the second form with the code received by mail to log in' // @translate
                    );
                    $session = $sessionManager->getStorage();
                    $session->offsetSet('tfa_user_email', $user->getEmail());
                    $this->getRequest()->setMetadata('first', true);
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
}
