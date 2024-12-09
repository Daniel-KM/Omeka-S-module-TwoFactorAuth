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
    ],
    'form_elements' => [
        'invokables' => [
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
        'user_settings' => [
            'twofactorauth_active' => false,
        ],
    ],
];
