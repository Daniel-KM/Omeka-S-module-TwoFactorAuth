<?php declare(strict_types=1);

namespace TwoFactorAuth;

return [
    'service_manager' => [
        'delegators' => [
            'Omeka\AuthenticationService' => [
                Service\Delegator\AuthenticationServiceDelegatorFactory::class,
            ],
        ],
    ],
    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
        ],
        'controller_map' => [
            Controller\LoginController::class => 'omeka/login',
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
            Form\TokenForm::class => Form\TokenForm::class,
            Form\UserSettingsFieldset::class => Form\UserSettingsFieldset::class,
        ],
    ],
    'controllers' => [
        'delegators' => [
            'Omeka\Controller\Login' => [
                Service\Delegator\LoginControllerDelegatorFactory::class,
            ],
        ],
    ],
    'controller_plugins' => [
        'factories' => [
            'twoFactorLogin' => Service\ControllerPlugin\TwoFactorLoginFactory::class,
        ],
    ],
    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => dirname(__DIR__) . '/language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],
    'twofactorauth' => [
        'config' => [
            'twofactorauth_force_2fa' => false,
            'twofactorauth_expiration_duration' => 1200,
            'twofactorauth_message_subject' => '[{site_title}] {token} is your code to log in', // @translate
            'twofactorauth_message_body' => <<<'TXT'
                Hi {user_name},
                The token to copy-paste to log in on {site_title} is:
                {token}
                Good browsing!
                If you did not request this email, please disregard it.
                TXT, // @translate
            'twofactorauth_use_dialog' => false,
        ],
        'user_settings' => [
            'twofactorauth_active' => false,
        ],
    ],
];
