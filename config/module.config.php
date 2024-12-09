<?php declare(strict_types=1);

namespace TwoFactorAuth;

return [
    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
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
