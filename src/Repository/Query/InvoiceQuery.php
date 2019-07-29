<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Repository\Query;

use App\Entity\InvoiceTemplate;

/**
 * Can be used for invoice queries.
 */
class InvoiceQuery extends TimesheetQuery
{
    /**
     * @var InvoiceTemplate
     */
    private $template;

    /**
     * @return InvoiceTemplate
     */
    public function getTemplate()
    {
        return $this->template;
    }

    /**
     * @param InvoiceTemplate $template
     * @return InvoiceQuery
     */
    public function setTemplate($template)
    {
        $this->template = $template;

        return $this;
    }
}
