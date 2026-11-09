<?php declare(strict_types=1);

namespace TwoFactorAuth;

/**
 * @var Module $this
 * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
 * @var string $newVersion
 * @var string $oldVersion
 *
 * @var \Omeka\Api\Manager $api
 * @var \Omeka\View\Helper\Url $url
 * @var \Omeka\Settings\Settings $settings
 * @var \Doctrine\DBAL\Connection $connection
 * @var \Doctrine\ORM\EntityManager $entityManager
 * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
 */
$plugins = $services->get('ControllerPluginManager');
$helpers = $services->get('ViewHelperManager');
$url = $helpers->get('url');
$api = $plugins->get('api');
$settings = $services->get('Omeka\Settings');
$translate = $plugins->get('translate');
$translator = $services->get('MvcTranslator');
$connection = $services->get('Omeka\Connection');
$messenger = $plugins->get('messenger');
$entityManager = $services->get('Omeka\EntityManager');

if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.96')) {
    $message = new \Omeka\Stdlib\Message(
        $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
        'Common', '3.4.96'
    );
    $messenger->addError($message);
    throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $translate('Missing requirement. Unable to upgrade.')); // @translate
}

if (version_compare($oldVersion, '3.4.4', '<')) {
    // The index may already exist on reinstalls.
    $hasIndex = (bool) $connection->executeQuery(
        "SHOW INDEX FROM `tfa_token` WHERE `Key_name` = 'idx_user_code'"
    )->fetchOne();
    if (!$hasIndex) {
        $connection->executeStatement('CREATE INDEX idx_user_code ON tfa_token (user_id, code)');
    }

    // Idempotent.
    $connection->executeStatement('ALTER TABLE tfa_token MODIFY code INT UNSIGNED NOT NULL');
}
