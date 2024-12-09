<?php declare(strict_types=1);

namespace TwoFactorAuth\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container as SessionContainer;
use Laminas\View\Model\ViewModel;
use Omeka\Controller\LoginController as OmekaLoginController;
use Omeka\Form\LoginForm;
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

        /**
         * @var \Laminas\Http\PhpEnvironment\Request $request
         * @var \TwoFactorAuth\Mvc\Controller\Plugin\TwoFactorLogin $twoFactorLogin
         */

        // The TokenForm returns to the login action, so check it when needed.
        $request = $this->getRequest();
        if ($request->isPost() && $request->getPost('submit_token')) {
            return $this->loginTokenAction();
        }

        $form = $this->getForm(LoginForm::class);

        if ($this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form->setData($data);
            if ($form->isValid()) {
                $validatedData = $form->getData();
                $email = $validatedData['email'];
                $password = $validatedData['password'];
                $twoFactorLogin = $this->twoFactorLogin();
                $requireSecondFactor = $twoFactorLogin->requireSecondFactor($email);
                if (!$requireSecondFactor) {
                    // This is simpler to use real login controller even if
                    // there is some repetitions of form checks.
                    $realAdapter = $twoFactorLogin->realAuthenticationAdapter();
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

                $result = $twoFactorLogin->validateLoginStep1($email, $password);
                if ($result) {
                    $user = $twoFactorLogin->userFromEmail($email);
                    $result = $twoFactorLogin->prepareLoginStep2($user);
                    if (!$result) {
                        return $this->redirect()->toRoute('login');
                    }
                    // Go to second step.
                    return $this->forward()->dispatch('Omeka\Controller\Login', [
                        'controller' => 'Omeka\Controller\Login',
                        'action' => 'login-token',
                    ]);
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
     * @see \Guest\Controller\Site\AnonymousController::loginToken()
     * @see \TwoFactorAuth\Controller\LoginController::loginTokenAction()
     */
    public function loginTokenAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')
                ? $this->redirect()->toRoute('admin')
                : $this->redirect()->toRoute('top');
        }

        /**
         * @var \Laminas\Http\PhpEnvironment\Request $request
         * @var \TwoFactorAuth\Form\TokenForm $form
         */
        $request = $this->getRequest();

        // Check if the first step was just processed.
        $isFirst = (bool) $request->getMetadata('first');

        if (!$isFirst && $this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form = $this->getForm(TokenForm::class);
            $form->setData($data);
            if ($form->isValid()) {
                /**
                 * @var \Laminas\Http\PhpEnvironment\Request $request
                 * @var \TwoFactorAuth\Mvc\Controller\Plugin\TwoFactorLogin $twoFactorLogin
                 */
                $validatedData = $form->getData();
                $twoFactorLogin = $this->twoFactorLogin();
                $result = $twoFactorLogin->validateLoginStep2($validatedData['token_email']);
                if ($result === null) {
                    return $this->redirect()->toRoute('login');
                } elseif ($result) {
                    $sessionManager = SessionContainer::getDefaultManager();
                    $session = $sessionManager->getStorage();
                    if ($redirectUrl = $session->offsetGet('redirect_url')) {
                        return $this->redirect()->toUrl($redirectUrl);
                    }
                    return $this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')
                        ? $this->redirect()->toRoute('admin')
                        : $this->redirect()->toRoute('top');
                }
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        $view = new ViewModel([
            'formToken' => $this->getForm(TokenForm::class),
        ]);
        return $view
            ->setTemplate('omeka/login/login-token');
    }
}
