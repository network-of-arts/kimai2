<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Configuration;

class ExportConfiguration implements SystemBundleConfiguration
{

    use StringAccessibleConfigTrait;

    public function getPrefix() : string
    {
        return 'export';
    }

    public function doDisplayCostOnPdf() : bool
    {
        return (bool)$this->find('pdf.display_cost');
    }
}
