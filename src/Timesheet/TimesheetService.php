<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Timesheet;

use App\Configuration\TimesheetConfiguration;
use App\Entity\Timesheet;
use App\Entity\User;
use App\Event\TimesheetMetaDefinitionEvent;
use App\Repository\TimesheetRepository;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class TimesheetService
{
    /**
     * @var TimesheetRepository
     */
    private $repository;
    /**
     * @var TimesheetConfiguration
     */
    private $configuration;
    /**
     * @var TrackingModeService
     */
    private $trackingModeService;
    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;
    /**
     * @var AuthorizationCheckerInterface
     */
    private $auth;

    public function __construct(
        TimesheetConfiguration $configuration,
        TimesheetRepository $repository,
        TrackingModeService $service,
        EventDispatcherInterface $dispatcher,
        AuthorizationCheckerInterface $security
    ) {
        $this->configuration = $configuration;
        $this->repository = $repository;
        $this->trackingModeService = $service;
        $this->dispatcher = $dispatcher;
        $this->auth = $security;
    }

    /**
     * Calls prepareNewTimesheet() automatically.
     *
     * @param User $user
     * @param Request|null $request
     * @return Timesheet
     */
    public function createNewTimesheet(User $user, ?Request $request = null): Timesheet
    {
        $timesheet = new Timesheet();
        $timesheet->setUser($user);

        if (null !== $request) {
            $this->prepareNewTimesheet($timesheet, $request);
        }

        return $timesheet;
    }

    public function prepareNewTimesheet(Timesheet $timesheet, ?Request $request = null)
    {
        if (null !== $timesheet->getId()) {
            throw new \InvalidArgumentException('Cannot prepare timesheet, already persisted');
        }

        $event = new TimesheetMetaDefinitionEvent($timesheet);
        $this->dispatcher->dispatch($event);

        $mode = $this->trackingModeService->getActiveMode();
        $mode->create($timesheet, $request);

        return $timesheet;
    }

    public function saveNewTimesheet(Timesheet $timesheet)
    {
        if (null !== $timesheet->getId()) {
            throw new \InvalidArgumentException('Cannot create timesheet, already persisted');
        }

        if (null === $timesheet->getEnd()) {
            if (!$this->auth->isGranted('start', $timesheet)) {
                throw new AccessDeniedHttpException('You are not allowed to start this timesheet record');
            }
            $this->repository->stopActiveEntries(
                $timesheet->getUser(),
                $this->configuration->getActiveEntriesHardLimit()
            );
        }

        $this->repository->save($timesheet);

        return $timesheet;
    }

    public function stopTimesheet(Timesheet $timesheet)
    {
        return $this->repository->stopRecording($timesheet);
    }
}
