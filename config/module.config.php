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
    'controllers' => [
        'delegators' => [
            'Omeka\Controller\Login' => [
                Service\Delegator\LoginControllerDelegatorFactory::class,
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
            'twofactorauth_expiration_duration' => 1200,
        ],
        'user_settings' => [
            'twofactorauth_active' => false,
        ],
    ],
];
