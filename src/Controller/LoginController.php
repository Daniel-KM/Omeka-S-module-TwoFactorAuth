<?php declare(strict_types=1);

namespace TwoFactorAuth\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Response;
use Laminas\I18n\Translator\TranslatorAwareInterface;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container as SessionContainer;
use Laminas\View\Model\JsonModel;
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
        $isPost = $request->isPost();
        if ($isPost
            && ($request->getPost('token_email') || $request->getPost('submit_token'))
        ) {
            return $this->loginTokenAction();
        }

        if (!$isPost && $request->getQuery('resend_token')) {
            return $this->resendTokenAction();
        }

        $form = $this->getForm(LoginForm::class);
        $isAjax = $request->isXmlHttpRequest();

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
                    if ($isAjax) {
                        $result = $twoFactorLogin->processLogin($email, $password);
                        return $result
                            ? $this->jSend('success', ['login' => true])
                            : $this->jSend('fail', [
                                'login' => false,
                                'message' => $this->translatedMessages('error') ?: $this->translate('Email or password is invalid'), // @translate
                            ]);
                    }
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
                        if ($isAjax) {
                            return $this->jSend('error');
                        }
                        return class_exists('Guest\Module')
                            ? $this->redirect()->toRoute('site/guest/anonymous', ['action' => 'login'], true)
                            : $this->redirect()->toRoute('login');
                    }
                    // Go to second step.
                    if ($isAjax) {
                        return $this->jSend('success', [
                            'login' => null,
                            'token_email' => null,
                            'dialog' => $this->viewHelpers()->get('partial')('omeka/login/token-dialog', [
                                'formToken' => $this->getForm(TokenForm::class)->setAttribute('action', $this->url()->fromRoute('login')),
                            ]),
                        ]);
                    }
                    return $this->forward()->dispatch('Omeka\Controller\Login', [
                        'controller' => 'Omeka\Controller\Login',
                        'action' => 'login-token',
                    ]);
                }
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        if ($isAjax) {
            return $this->jSend('error', [], $this->translate('Ajax login form is not implemented here. Use Guest page instead.')); // @translate
        }

        $view = new ViewModel([
            'form' => $form,
        ]);
        if ($this->settings()->get('twofactorauth_use_dialog')) {
            $view
                ->setVariable('formToken', $this->getForm(TokenForm::class)->setAttribute('action', $this->url()->fromRoute('login')))
                ->setTemplate('omeka/login/login-2fa');
        }
        return $view;
    }

    /**
     * @see \Guest\Controller\Site\AnonymousController::loginToken()
     * @see \Guest\Site\BlockLayout\Login::loginToken()
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
        $isAjax = $request->isXmlHttpRequest();

        // Check if the first step was just processed.
        $isFirst = (bool) $request->getMetadata('first');

        if (!$isFirst && $this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form = $this->getForm(TokenForm::class)->setAttribute('action', $this->url()->fromRoute('login'));
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
                    if ($isAjax) {
                        return $this->jSend('error');
                    }
                    return class_exists('Guest\Module')
                        ? $this->redirect()->toRoute('site/guest/anonymous', ['action' => 'login'], true)
                        : $this->redirect()->toRoute('login');
                } elseif ($result) {
                    if ($isAjax) {
                        return $this->jSend('success', ['login' => true]);
                    }
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

        if ($isAjax) {
            // IsFirst is normally not possible for json (already sent in loginAction).
            if ($isFirst) {
                return $this->jSend('success', [
                    'login' => null,
                    'token_email' => null,
                    'dialog' => $this->viewHelpers()->get('partial')('omeka/login/token-dialog', [
                        'formToken' => $this->getForm(TokenForm::class)->setAttribute('action', $this->url()->fromRoute('login')),
                    ]),
                ]);
            } else {
                return $this->jSend('fail', [
                    'login' => null,
                    'token_email' => $this->translatedMessages('error') ?: $this->translate('Invalid code'), // @translate
                    // Don't resend dialog.
                ]);
            }
        }

        $view = new ViewModel([
            'formToken' => $this->getForm(TokenForm::class),
        ]);
        return $view
            ->setTemplate('omeka/login/login-token');
    }

    /**
     * Adapted:
     * @see \Guest\Controller\Site\AnonymousController::resendToken();
     * @see \Guest\Site\BlockLayout\Login::resendToken()
     * @see \TwoFactorAuth\Controller\LoginController::resendTokenAction();
     */
    protected function resendTokenAction()
    {
        $request = $this->getRequest();
        $codeKey = $request->getQuery('resend_token');
        if ($codeKey) {
            $twoFactorLogin = $this->twoFactorLogin();
            $result = $twoFactorLogin->resendToken();
        } else {
            $result = false;
        }

        $isAjax = $request->isXmlHttpRequest() || $request->getQuery('ajax');
        if ($isAjax) {
            if ($result) {
                return $this->jSend('success', [
                    'login' => null,
                    'token_email' => null,
                    'message' => $this->translate('A new code was resent.'), // @translate
                ]);
            } else {
                return $this->jSend('error', [], $this->translate('Unable to send email.')); // @translate
            }
        }

        $result
            ? $this->messenger()->addSuccess('A new code was resent.')
            :  $this->messenger()->addError('Unable to send email.');

        $view = new ViewModel([
            'formToken' => $this->getForm(TokenForm::class),
        ]);
        return $view
            ->setTemplate('omeka/login/login-token');
    }

    /**
     * Send output via json according to jSend.
     *
     * For status fail and error, the error messages are taken from messenger
     * messages  when not set.
     *
     * @see https://github.com/omniti-labs/jsend
     *
     * @throws \Laminas\Mvc\Exception\RuntimeException
     * @deprecated Use \Common\Mvc\Controller\Plugin\JSend (since Common version 3.4.65).
     */
    protected function jSend(
        string $status,
        array $data = [],
        ?string $message = null,
        ?int $code = null,
        ?int $httpStatusCode = null
    ) {
        switch ($status) {
            case 'success':
                $json = [
                    'status' => 'success',
                    'data' => $data,
                ];
                break;

            case 'fail':
                if (!$data) {
                    $message = $message
                        ?: $this->translatedMessages('error')
                        ?: $this->translate('Check your input for invalid data.'); // @translate
                    $data = ['fail' => $message];
                }
                $json = [
                    'status' => 'fail',
                    'data' => $data,
                ];
                $httpStatusCode ??= Response::STATUS_CODE_400;
                break;

            case 'error':
            default:
                $message = $message
                    ?: $this->translatedMessages('error')
                    ?: $this->translate('An internal error has occurred.'); // @translate
                $json = [
                    'status' => 'error',
                    'message' => $message,
                ];
                if ($data) {
                    $json['data'] = $data;
                }
                if ($code) {
                    $json['code'] = $code;
                }
                $httpStatusCode ??= Response::STATUS_CODE_500;
                break;
        }

        if ($httpStatusCode) {
            /** @var \Laminas\Http\Response $response */
            $response = $this->getResponse();
            $response->setStatusCode($httpStatusCode);
        }

        return new JsonModel($json);
    }

    /**
     * @deprecated Use $this->viewHelpers()->get('messages')->getTranslatedMessages() (since Common version 3.4.65).
     */
    protected function translatedMessages(string $type, bool $asArray = false)
    {
        /** @var \Common\View\Helper\Messages $messages */
        $messages = $this->viewHelpers()->get('messages');
        if (method_exists($messages, 'getTranslatedMessages')) {
            $msgs = $messages->getTranslatedMessages();
        } else {
            $translate = $this->translate();
            $translator = $translate->getTranslator();
            $msgs = array_map(
                fn ($msg) => $msg instanceof TranslatorAwareInterface
                    ? $msg->setTranslator($translator)->translate()
                    : $translate($msg),
                $messages->get()
            );
        }

        $msgs = $msgs[$type] ?? [];
        return $asArray
            ? $msgs
            : implode("\n", $msgs);
    }
}
