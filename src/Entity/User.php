<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use FOS\UserBundle\Model\User as BaseUser;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * @ORM\Entity(repositoryClass="App\Repository\UserRepository")
 * @ORM\Table(name="kimai2_users",
 *      uniqueConstraints={
 *          @ORM\UniqueConstraint(columns={"username"}),
 *          @ORM\UniqueConstraint(columns={"email"})
 *      }
 * )
 * @UniqueEntity("username")
 * @UniqueEntity("email")
 */
class User extends BaseUser implements UserInterface
{
    public const ROLE_USER = 'ROLE_USER';
    public const ROLE_TEAMLEAD = 'ROLE_TEAMLEAD';
    public const ROLE_ADMIN = 'ROLE_ADMIN';
    public const ROLE_SUPER_ADMIN = 'ROLE_SUPER_ADMIN';

    public const DEFAULT_ROLE = self::ROLE_USER;
    public const DEFAULT_LANGUAGE = 'en';

    /**
     * @var int
     *
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(name="id", type="integer")
     */
    protected $id;

    /**
     * @var string
     *
     * @ORM\Column(name="alias", type="string", length=60, nullable=true)
     * @Assert\Length(max=160)
     */
    private $alias;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="registration_date", type="datetime", nullable=true)
     */
    private $registeredAt;

    /**
     * @var string
     *
     * @ORM\Column(name="title", type="string", length=50, nullable=true)
     */
    private $title;

    /**
     * @var string
     *
     * @ORM\Column(name="avatar", type="string", length=255, nullable=true)
     */
    private $avatar;

    /**
     * @var string
     *
     * @ORM\Column(name="api_token", type="string", length=255, nullable=true)
     */
    protected $apiToken;

    /**
     * @var string
     */
    protected $plainApiToken;

    /**
     * @var UserPreference[]|Collection
     *
     * @ORM\OneToMany(targetEntity="App\Entity\UserPreference", mappedBy="user", cascade={"persist"})
     */
    private $preferences;

    /**
     * User constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->registeredAt = new \DateTime();
        $this->preferences = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getRegisteredAt(): ?\DateTime
    {
        return $this->registeredAt;
    }

    public function setRegisteredAt(\DateTime $registeredAt): User
    {
        $this->registeredAt = $registeredAt;

        return $this;
    }

    public function setAlias(?string $alias): User
    {
        $this->alias = $alias;

        return $this;
    }

    public function getAlias(): ?string
    {
        return $this->alias;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function setTitle(?string $title): User
    {
        $this->title = $title;

        return $this;
    }

    public function getAvatar(): ?string
    {
        return $this->avatar;
    }

    public function setAvatar(?string $avatar): User
    {
        $this->avatar = $avatar;

        return $this;
    }

    public function getApiToken(): ?string
    {
        return $this->apiToken;
    }

    public function setApiToken(?string $apiToken): User
    {
        $this->apiToken = $apiToken;

        return $this;
    }

    public function getPlainApiToken(): ?string
    {
        return $this->plainApiToken;
    }

    public function setPlainApiToken(?string $plainApiToken): User
    {
        $this->plainApiToken = $plainApiToken;

        return $this;
    }

    /**
     * @return Collection<UserPreference>
     */
    public function getPreferences(): Collection
    {
        return $this->preferences;
    }

    /**
     * @param iterable<UserPreference> $preferences
     * @return User
     */
    public function setPreferences(iterable $preferences): User
    {
        $this->preferences = new ArrayCollection();

        foreach ($preferences as $preference) {
            $this->addPreference($preference);
        }

        return $this;
    }

    /**
     * @param string $name
     * @param bool|int|string|null $value
     */
    public function setPreferenceValue(string $name, $value = null)
    {
        $pref = $this->getPreference($name);

        if (null === $pref) {
            $pref = new UserPreference();
            $pref->setName($name);
            $this->addPreference($pref);
        }

        $pref->setValue($value);
    }

    public function getPreference(string $name): ?UserPreference
    {
        // this code will be triggered, if a currently logged-in user will be deleted and the refreshed from the session
        // via one of the UserProvider - e.g. see LdapUserProvider::refreshUser() which calls $user->getPreferenceValue()
        if (empty($this->preferences)) {
            return null;
        }

        foreach ($this->preferences as $preference) {
            if ($preference->getName() == $name) {
                return $preference;
            }
        }

        return null;
    }

    /**
     * @return string
     */
    public function getLocale(): string
    {
        return $this->getPreferenceValue(UserPreference::LOCALE, User::DEFAULT_LANGUAGE);
    }

    /**
     * @param string $name
     * @param mixed $default
     * @return bool|int|null|string
     */
    public function getPreferenceValue($name, $default = null)
    {
        $preference = $this->getPreference($name);
        if (null === $preference) {
            return $default;
        }

        return $preference->getValue();
    }

    /**
     * @param UserPreference $preference
     * @return User
     */
    public function addPreference(UserPreference $preference): User
    {
        $this->preferences->add($preference);
        $preference->setUser($this);

        return $this;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->getAlias() ?: $this->getUsername();
    }
}
