<?php declare(strict_types=1);

namespace TwoFactorAuth\Authentication\Adapter;

use DateTime;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityRepository;
use Laminas\Authentication\Adapter\AbstractAdapter;
use Laminas\Authentication\Adapter\AdapterInterface as AuthAdapterInterface;
use Laminas\Authentication\Result;
use Omeka\Entity\User;
use Omeka\Settings\UserSettings;
use TwoFactorAuth\Entity\Token;

/**
 * Auth adapter for checking passwords through Doctrine.
 *
 * Same as omeka password manager, except a check of the two factor auth token.
 * Compatible with modules Guest and UserNames.
 *
 * Because the steps are managed via the login controller, the token adapter is
 * nearly like password adapter with a one-time automatically defined password.
 * Keep the delegator to manage users who didn't activate 2fa.
 *
 * @todo Check if the use of CallbackCheckAdapter is simpler.
 * @see https://docs.laminas.dev/laminas-authentication/adapter/dbtable/callback-check#adding-criteria-to-match
 */
class TokenAdapter extends AbstractAdapter
{
    /**
     * @var \Doctrine\DBAL\Connection
     */
    protected $connection;

    /**
     * @var \Doctrine\ORM\EntityManager
     */
    protected $entityManager;

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
    protected $tokenRepository;

    /**
     * @var \Doctrine\ORM\EntityRepository
     */
    protected $userRepository;

    /**
     * @var \Omeka\Settings\UserSettings
     */
    protected $userSettings;

    /**
     * Number of seconds before expiration of tokens.
     *
     * @var int
     */
    protected $expirationDuration = 1200;

    /**
     * @var bool
     */
    protected $force2fa = false;

    public function __construct(
        AuthAdapterInterface $realAdapter,
        Connection $connection,
        EntityManager $entityManager,
        EntityRepository $tokenRepository,
        EntityRepository $userRepository,
        UserSettings $userSettings,
        int $expirationDuration,
        bool $force2fa
    ) {
        $this->realAdapter = $realAdapter;
        $this->connection = $connection;
        $this->entityManager = $entityManager;
        $this->tokenRepository = $tokenRepository;
        $this->userRepository = $userRepository;
        $this->userSettings = $userSettings;
        $this->expirationDuration = $expirationDuration;
        $this->force2fa = $force2fa;
    }

    public function authenticate()
    {
        // The first factor is already managed during the first step in the real
        // adapter.

        $user = $this->userRepository->findOneBy(['email' => $this->identity]);
        if (!$user || !$user->isActive()) {
            return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, null,
                ['User not found.']);
        }

        // Normally, this check is done in the first step.
        // It is a quick one anyway.
        if (!$this->requireSecondFactor($user)) {
            return new Result(Result::SUCCESS, $user);
        }

        // Manage the second factor authentication.

        if (!$this->credential) {
            return new Result(
                Result::FAILURE_CREDENTIAL_INVALID,
                null,
                ['Missing two-factor authentication code.'] // @translate
            );
        }

        // Clear old tokens first.
        $this->cleanTokens();

        // Check token. A user may request multiple times the code.
        $token = $this->tokenRepository->findOneBy([
            'user' => $user,
            'code' => $this->credential,
        ]);
        if (!$token) {
            return new Result(
                Result::FAILURE_CREDENTIAL_INVALID,
                null,
                ['Invalid or expired code.'] // @translate
            );
        }

        // Clear all tokens of the user.
        $this->cleanTokens($user);

        return new Result(Result::SUCCESS, $user);
    }

    /**
     * Check if the user has set the two-factor authentication.
     */
    public function requireSecondFactor(User $user): bool
    {
        return $this->force2fa
            || $this->userSettings->get('twofactorauth_active', false, $user->getId());
    }

    public function getRealAdapter(): AuthAdapterInterface
    {
        return $this->realAdapter;
    }

    public function getTokenRepository(): EntityRepository
    {
        return $this->tokenRepository;
    }

    public function getUserRepository(): EntityRepository
    {
        return $this->userRepository;
    }

    public function createToken(User $user): Token
    {
        // Don't use random integer directly to avoid repetitive digits.
        // But allow two times the same digit, except 0.
        $available = '0123456789123456789';
        $code = (int) substr(str_shuffle($available), 0, 4);
        $token = new Token();
        $token
            ->setUser($user)
            ->setCode($code)
            // Warning: DateTime('now') is the time of the php server, that may
            // be different from the database server with utc or different time
            // offset.
            // Furthermore, Current_Timestamp is supported only with mysql.
            ->setCreated(new DateTime('now'));
        $this->entityManager->persist($token);
        $this->entityManager->flush();
        return $token;
    }

    /**
     * Expire old 2FA tokens and user ones.
     *
     * To manage tokens here simplify integration.
     */
    public function cleanTokens(?User $user = null): self
    {
        // Use a direct query, because there is no side effects neither log.
        $qb = $this->connection->createQueryBuilder();
        $expr = $qb->expr();
        $qb
            ->delete('tfa_token')
            // Don't use Current_Timestamp, but DateTime('now') everywhere to
            // avoid issues with time offsets.
            ->where($expr->lt('created', 'DATE_SUB(:current_timestamp, INTERVAL :duration SECOND)'))
            ->setParameter('current_timestamp', (new DateTime('now'))->format('Y-m-d H:i:s'), ParameterType::STRING)
            ->setParameter('duration', $this->expirationDuration, ParameterType::INTEGER);
        if ($user) {
            $qb
                ->orWhere($expr->eq('user_id', ':user_id'))
                ->setParameter('user_id', $user->getId(), ParameterType::INTEGER);
        }
        $qb->execute();
        return $this;
    }
}
