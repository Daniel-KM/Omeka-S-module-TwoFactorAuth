<?php declare(strict_types=1);

namespace TwoFactorAuth\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;

class TokenForm extends Form
{
    public function init(): void
    {
        $this
            ->add([
                'name' => 'token_email',
                'type' => Element\Number::class,
                'options' => [
                    'label' => 'Four-digit code', // @translate
                ],
                'attributes' => [
                    'id' => 'token_email',
                    'required' => true,
                    'min' => 0,
                    'max' => 9999,
                    'step' => 1,
                ],
            ])
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
