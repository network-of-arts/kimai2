<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Repository;

use App\Repository\Query\TagQuery;
use Doctrine\ORM\EntityRepository;

class TagRepository extends EntityRepository
{
    use RepositoryTrait;

    /**
     * Find ids of the given tagNames separated by comma
     * @param string $tagNames
     * @return array
     */
    public function findIdsByTagNameList($tagNames)
    {
        $qb = $this
            ->createQueryBuilder('t')
            ->select('t.id');
        $list = array_filter(array_unique(array_map('trim', explode(',', $tagNames))));
        $cnt = 0;
        foreach ($list as $listElem) {
            $qb
                ->orWhere('t.name like :elem' . $cnt)
                ->setParameter('elem' . $cnt, '%' . $listElem . '%');
            $cnt++;
        }

        return array_column($qb->getQuery()->getScalarResult(), 'id');
    }

    /**
     * Find all tag names in an alphabetical order
     *
     * @param string $filter
     * @return array
     */
    public function findAllTagNames($filter = null)
    {
        $qb = $this->createQueryBuilder('t');

        $qb
            ->select('t.name')
            ->addOrderBy('t.name', 'ASC');

        if (null !== $filter) {
            $qb
                ->andWhere('t.name LIKE :filter')
                ->setParameter('filter', '%' . $filter . '%');
        }

        return array_column($qb->getQuery()->getScalarResult(), 'name');
    }

    /**
     * Returns an array of arrays with each inner array having the structure:
     * - id
     * - name
     * - amount
     *
     * @param TagQuery $query
     * @return array|\Doctrine\ORM\QueryBuilder|\Pagerfanta\Pagerfanta
     */
    public function getTagCount(TagQuery $query)
    {
        $qb = $this->createQueryBuilder('tag');

        $qb
            ->select('tag.id, tag.name, count(timesheets.id) as amount')
            ->leftJoin('tag.timesheets', 'timesheets')
            ->addGroupBy('tag.id')
            ->addGroupBy('tag.name')
            ->orderBy('tag.name')
        ;

        return $this->getBaseQueryResult($qb, $query);
    }
}
