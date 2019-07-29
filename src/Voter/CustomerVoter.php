<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Voter;

use App\Entity\Customer;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * A voter to check permissions on Customers.
 */
class CustomerVoter extends AbstractVoter
{
    public const VIEW = 'view';
    public const EDIT = 'edit';
    public const BUDGET = 'budget';
    public const DELETE = 'delete';

    /**
     * support rules based on the given $subject (here: Customer)
     */
    public const ALLOWED_ATTRIBUTES = [
        self::VIEW,
        self::EDIT,
        self::BUDGET,
        self::DELETE,
    ];

    /**
     * @param string $attribute
     * @param Customer $subject
     * @return bool
     */
    protected function supports($attribute, $subject)
    {
        if (!($subject instanceof Customer)) {
            return false;
        }

        if (!in_array($attribute, self::ALLOWED_ATTRIBUTES)) {
            return false;
        }

        return true;
    }

    /**
     * @param string $attribute
     * @param Customer $subject
     * @param TokenInterface $token
     * @return bool
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        return $this->hasRolePermission($user, $attribute . '_customer');
    }
}
