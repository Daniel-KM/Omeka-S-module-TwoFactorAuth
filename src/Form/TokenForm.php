<?php declare(strict_types=1);

namespace TwoFactorAuth\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;

class TokenForm extends Form
{
    public function init(): void
    {
        $this
            ->setAttribute('id', 'login-token-form')
            ->setAttribute('class', 'login-token-form disable-unsaved-warning')
            ->add([
                'name' => 'token_email',
                'type' => Element\Number::class,
                'options' => [
                    'label' => 'Code', // @translate
                ],
                'attributes' => [
                    'id' => 'token_email',
                    'required' => true,
                    'min' => 0,
                    'max' => 9999,
                    'step' => 1,
                ],
            ])
            // TODO Button for spin wait.
            ->add([
                'name' => 'submit_token',
                'type' => Element\Submit::class,
                'attributes' => [
                    'value' => 'Submit', // @translate
                ],
            ])
        ;
    }
}
