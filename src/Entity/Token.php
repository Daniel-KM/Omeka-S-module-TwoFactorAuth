<?php declare(strict_types=1);

namespace TwoFactorAuth\Entity;

use DateTime;
use Omeka\Entity\AbstractEntity;
use Omeka\Entity\User;

/**
 * This entity is not available via omeka api.
 * The token is removed once validated.
 *
 * @Entity
 * @Table(
 *     name="tfa_token"
 * )
 */
class Token extends AbstractEntity
{
    /**
     * @var int
     *
     * @Id
     * @Column(
     *     type="integer"
     * )
     * @GeneratedValue
     */
    protected $id;

    /**
     * @var User
     *
     * A user can require multipe token when the mail is slow.
     * The number is limited internally.
     *
     * @ManyToOne(
     *     targetEntity="\Omeka\Entity\User"
     * )
     * @JoinColumn(
     *     nullable=false,
     *     onDelete="CASCADE"
     * )
     */
    protected $user;

    /**
     * @var int
     *
     * @Column(
     *     type="integer"
     * )
     */
    protected $code;

    /**
     * @var DateTime
     *
     * @Column(
     *     type="datetime",
     *     nullable=false,
     *     options={
     *         "default": "CURRENT_TIMESTAMP"
     *     }
     * )
     */
    protected $created;

    public function getId()
    {
        return $this->id;
    }

    public function setUser(User $user): self
    {
        $this->user = $user;
        return $this;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function setCode(int $code): self
    {
        $this->code = $code;
        return $this;
    }

    public function getCode(): int
    {
        return $this->code;
    }

    public function setCreated(DateTime $created): self
    {
        $this->created = $created;
        return $this;
    }

    public function getCreated(): DateTime
    {
        return $this->created;
    }
}
