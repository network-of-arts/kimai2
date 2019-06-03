<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Export\Renderer;

use App\Entity\Timesheet;

trait RendererTrait
{
    /**
     * @param Timesheet[] $timesheets
     * @return array
     */
    protected function calculateSummary(array $timesheets)
    {
        $summary = [];

        foreach ($timesheets as $timesheet) {
            $id = $timesheet->getProject()->getCustomer()->getId() . '_' . $timesheet->getProject()->getId();
            $activityId = $timesheet->getActivity()->getId();

            if (!isset($summary[$id])) {
                $summary[$id] = [
                    'customer' => $timesheet->getProject()->getCustomer()->getName(),
                    'project' => $timesheet->getProject()->getName(),
                    'activities' => [],
                    'currency' => $timesheet->getProject()->getCustomer()->getCurrency(),
                    'rate' => 0,
                    'duration' => 0,
                ];
            }

            if (!isset($summary[$id]['activities'][$activityId])) {
                $summary[$id]['activities'][$activityId] = [
                    'activity' => $timesheet->getActivity()->getName(),
                    'currency' => $timesheet->getProject()->getCustomer()->getCurrency(),
                    'rate' => 0,
                    'duration' => 0,
                ];
            }

            $summary[$id]['rate'] += $timesheet->getRate();
            $summary[$id]['duration'] += $timesheet->getDuration();
            $summary[$id]['activities'][$activityId]['rate'] += $timesheet->getRate();
            $summary[$id]['activities'][$activityId]['duration'] += $timesheet->getDuration();
        }

        asort($summary);

        return $summary;
    }

    protected function calculateUserSummary(array $timesheets)
    {
        $summary = [];

        foreach ($timesheets as $timesheet) {
            $id = $timesheet->getUser()->getAlias();

            if (!isset($summary[$id])) {
                $summary[$id] = [
                    'duration' => 0,
                    'customers' => [],
                    'projects' => []
                ];
            }

            $customerName = $timesheet->getProject()->getCustomer()->getName();
            $projectName = sprintf('%s / %s',
                $customerName,
                $timesheet->getProject()->getName());

            if (!isset($summary[$id]['customers'][$customerName])) {
                $summary[$id]['customers'][$customerName] = 0;
            }
            if (!isset($summary[$id]['projects'][$projectName])) {
                $summary[$id]['projects'][$projectName] = 0;
            }

            $summary[$id]['duration'] += $timesheet->getDuration();
            $summary[$id]['customers'][$customerName] += $timesheet->getDuration();
            $summary[$id]['projects'][$projectName] += $timesheet->getDuration();
        }

        asort($summary);

        return $summary;
    }
}
