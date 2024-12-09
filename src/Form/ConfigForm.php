<?php declare(strict_types=1);

namespace TwoFactorAuth\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;
use Omeka\Form\Element as OmekaElement;

class ConfigForm extends Form
{
    public function init(): void
    {
        $this
            ->add([
                'name' => 'twofactorauth_force_2fa',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Force all users to use 2FA', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_force_2fa',
                ],
            ])
            ->add([
                'name' => 'twofactorauth_expiration_duration',
                'type' => Element\Number::class,
                'options' => [
                    'label' => 'Expiration of token (seconds)', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_expiration_duration',
                    'min' => 0,
                    'max' => 86400,
                    'step' => 1,
                ],
            ])

            ->add([
                'name' => 'twofactorauth_message_subject',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Subject of the email sent to user', // @translate
                    'info' => 'Possible placeholders: {main_title}, {main_url}, {site_title}, {site_url}, {email}, {name}, {token}, {code}.', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_message_subject',
                    'placeholder' => '[{site_title}] {token} is your code to log in', // @translate
                ],
            ])
            ->add([
                'name' => 'twofactorauth_message_body',
                'type' => OmekaElement\CkeditorInline::class,
                'options' => [
                    'label' => 'Text of the email', // @translate
                    'info' => 'Possible placeholders: {main_title}, {main_url}, {site_title}, {site_url}, {email}, {name}, {token}, {code}.', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_message_body',
                    'placeholder' => <<<'TXT'
                        Hi {user_name},
                        The token to copy-paste to log in on {site_title} is:
                        {token}
                        Good browsing!
                        If you did not request this email, please disregard it.
                        TXT, // @translate
                ],
            ])

            ->add([
                'name' => 'twofactorauth_use_dialog',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Use a popup dialog for second step', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_use_dialog',
                ],
            ])
        ;
    }
}
