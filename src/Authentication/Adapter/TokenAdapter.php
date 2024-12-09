<?php declare(strict_types=1);

namespace TwoFactorAuth\Authentication\Adapter;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Doctrine\ORM\EntityRepository;
use Laminas\Authentication\Adapter\AdapterInterface as AuthAdapterInterface;
use Laminas\Authentication\Result;
use Omeka\Authentication\Adapter\PasswordAdapter;
use Omeka\Settings\UserSettings;

/**
 * Auth adapter for checking passwords through Doctrine.
 *
 * Same as omeka password manager, except a check of the two factor auth token.
 * Compatible with modules Guest and UserNames.
 *
 * @todo Check if the use of CallbackCheckAdapter is simpler.
 * @see https://docs.laminas.dev/laminas-authentication/adapter/dbtable/callback-check#adding-criteria-to-match
 */
class TokenAdapter extends PasswordAdapter
{
    /**
     * @var \Doctrine\DBAL\Connection
     */
    protected $connection;

    /**
     * @var \Laminas\Authentication\Adapter\AdapterInterface
     *
     * In most of the cases:
     * @see \Omeka\Authentication\Adapter\PasswordAdapter
     * @see \Guest\Authentication\Adapter\PasswordAdapter
     * @see \UserNames\Authentication\Adapter\PasswordAdapter
     */
    protected $realAdapter;

    /**
     * @var \Doctrine\ORM\EntityRepository
     */
    protected $tfaTokenRepository;

    /**
     * @var \Omeka\Settings\UserSettings
     */
    protected $userSettings;

    /**
     * @var int
     */
    protected $expirationDuration = 600;

    public function __construct(
        AuthAdapterInterface $realAdapter,
        Connection $connection,
        EntityRepository $tfaTokenRepository,
        UserSettings $userSettings
    ) {
        $this->realAdapter = $realAdapter;
        $this->connection = $connection;
        $this->setTfaTokenRepository($tfaTokenRepository);
        $this->setUserSettings($userSettings);
    }

    public function authenticate()
    {
        // Manage the first factor.

        /** @var \Laminas\Authentication\Result $result */
        $result = $this->realAdapter
            ->setIdentity($this->getIdentity())
            ->setCredential($this->getCredential())
            ->authenticate();
        if (!$result->isValid()) {
            return $result;
        }

        /** @var \Omeka\Entity\User $user */
        $user = $result->getIdentity();

         // Check if the user has set the two-factor authentication.
        if (!$this->userSettings->get('twofactorauth_active', false, $user->getId())) {
            return $result;
        }

        // Manage the second factor authentication.

        // TODO Use Laminas request and check csrf (even if normally already checked during first step).
        $token = $_POST['token'] ?? null;
        if (!$token) {
            return new Result(
                Result::FAILURE_CREDENTIAL_INVALID,
                null,
                ['Missing two-factor authentication code.'] // @translate
            );
        }

        // Clear old tokens first (to do it here simplify integration).
        // Use a direct query, because there is no side effects neither log.
        $sql = 'DELETE FROM `tfa_token` WHERE `created` < DATE_SUB(NOW(), INTERVAL :duration SECOND)';
        $this->connection->prepare($sql)
            ->bindValue('duration', $this->expirationDuration, ParameterType::INTEGER)
            ->executeStatement();

        // Check token.
        $tfaToken = $this->tfaTokenRepository->findOneBy([
            'user' => $user,
            'token' => $token,
        ]);
        if (!$tfaToken) {
            return new Result(
                Result::FAILURE_CREDENTIAL_INVALID,
                null,
                ['Invalid or expired code.'] // @translate
            );
        }

        return $result;
    }

    public function setTfaTokenRepository(EntityRepository $tfaTokenRepository): self
    {
        $this->tfaTokenRepository = $tfaTokenRepository;
        return $this;
    }

    public function setUserSettings(UserSettings $userSettings): self
    {
        $this->userSettings = $userSettings;
        return $this;
    }
}
