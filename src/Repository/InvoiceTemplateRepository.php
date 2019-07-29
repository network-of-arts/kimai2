<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Repository;

use App\Entity\InvoiceTemplate;
use App\Repository\Query\BaseQuery;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Pagerfanta\Pagerfanta;

class InvoiceTemplateRepository extends EntityRepository
{
    use RepositoryTrait;

    /**
     * @return bool
     */
    public function hasTemplate()
    {
        $qb = $this->getEntityManager()->createQueryBuilder();

        $qb->select('COUNT(t.id) as totalRecords')
            ->from(InvoiceTemplate::class, 't')
        ;

        $result = $qb->getQuery()->execute([], Query::HYDRATE_ARRAY);

        if (!isset($result[0])) {
            return false;
        }

        return $result[0]['totalRecords'] > 0;
    }

    /**
     * @param BaseQuery $query
     * @return QueryBuilder|Pagerfanta|array
     */
    public function findByQuery(BaseQuery $query)
    {
        $qb = $this->getEntityManager()->createQueryBuilder();

        $qb->select('t')
            ->from(InvoiceTemplate::class, 't')
            ->orderBy('t.name');

        return $this->getBaseQueryResult($qb, $query);
    }

    /**
     * @param InvoiceTemplate $template
     * @return InvoiceTemplate
     * @throws RepositoryException
     */
    public function saveTemplate(InvoiceTemplate $template)
    {
        try {
            $this->getEntityManager()->persist($template);
            $this->getEntityManager()->flush();
        } catch (\Exception $ex) {
            throw new RepositoryException('Could not save InvoiceTemplate');
        }

        return $template;
    }

    /**
     * @param InvoiceTemplate $template
     * @throws RepositoryException
     */
    public function removeTemplate(InvoiceTemplate $template)
    {
        try {
            $this->getEntityManager()->remove($template);
            $this->getEntityManager()->flush();
        } catch (\Exception $ex) {
            throw new RepositoryException('Could not remove InvoiceTemplate');
        }
    }
}
