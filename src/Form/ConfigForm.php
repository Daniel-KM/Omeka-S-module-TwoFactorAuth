<?php declare(strict_types=1);

namespace TwoFactorAuth\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;

class ConfigForm extends Form
{
    public function init()
    {
        $this
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
        ;
    }
}
