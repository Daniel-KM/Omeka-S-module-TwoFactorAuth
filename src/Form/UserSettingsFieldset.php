<?php declare(strict_types=1);

namespace TwoFactorAuth\Form;

use Laminas\Form\Element;
use Laminas\Form\Fieldset;

class UserSettingsFieldset extends Fieldset
{
    public function init(): void
    {
        $this
            ->add([
                'name' => 'twofactorauth_active',
                'type' => Element\Checkbox::class,
                'options' => [
                    'element_group' => 'user_settings',
                    'label' => 'Enable two-factor authentication with a code sent by email', // @translate
                ],
                'attributes' => [
                    'id' => 'twofactorauth_active',
                    'required' => false,
                ],
            ])
        ;
    }
}
