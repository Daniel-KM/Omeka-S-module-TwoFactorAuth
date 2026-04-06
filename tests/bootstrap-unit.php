<?php declare(strict_types=1);

require_once dirname(__DIR__, 3) . '/vendor/autoload.php';

$loader = new \Composer\Autoload\ClassLoader();
$loader->addPsr4('TwoFactorAuth\\', dirname(__DIR__) . '/src');
$loader->addPsr4('TwoFactorAuthTest\\', __DIR__ . '/TwoFactorAuthTest');
$loader->addPsr4('Common\\', dirname(__DIR__, 2) . '/Common/src');
$loader->register();

error_reporting(E_ALL);
ini_set('display_errors', '1');
