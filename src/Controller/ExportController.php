<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Controller;

use App\Entity\Timesheet;
use App\Export\ServiceExport;
use App\Form\Toolbar\ExportToolbarForm;
use App\Repository\Query\ExportQuery;
use App\Repository\TimesheetRepository;
use App\Timesheet\UserDateTimeFactory;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Controller used to export timesheet data.
 *
 * @Route(path="/export")
 * @Security("is_granted('view_export')")
 */
class ExportController extends AbstractController
{
    /**
     * @var TimesheetRepository
     */
    protected $timesheetRepository;

    /**
     * @var ServiceExport
     */
    protected $export;
    /**
     * @var UserDateTimeFactory
     */
    protected $dateFactory;

    /**
     * @param TimesheetRepository $timesheet
     * @param ServiceExport $export
     */
    public function __construct(TimesheetRepository $timesheet, ServiceExport $export, UserDateTimeFactory $dateTime)
    {
        $this->timesheetRepository = $timesheet;
        $this->export = $export;
        $this->dateFactory = $dateTime;
    }

    /**
     * @return ExportQuery
     * @throws \Exception
     */
    protected function getDefaultQuery()
    {
        $begin = $this->dateFactory->createDateTime('first day of this month 00:00:00');
        $end = $this->dateFactory->createDateTime('last day of this month 23:59:59');

        $query = new ExportQuery();
        $query->setOrder(ExportQuery::ORDER_ASC);
        $query->setBegin($begin);
        $query->setEnd($end);
        $query->setState(ExportQuery::STATE_STOPPED);
        $query->setExported(ExportQuery::STATE_NOT_EXPORTED);

        return $query;
    }

    /**
     * @Route(path="/", name="export", methods={"GET"})
     * @Security("is_granted('view_export')")
     *
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function indexAction(Request $request)
    {
        $query = $this->getDefaultQuery();

        $form = $this->getToolbarForm($query, 'GET');
        $form->setData($query);
        $form->submit($request->query->all(), false);

        $entries = $this->getEntries($query);

        return $this->render('export/index.html.twig', [
            'query' => $query,
            'entries' => $entries,
            'form' => $form->createView(),
            'renderer' => $this->export->getRenderer(),
        ]);
    }

    /**
     * @Route(path="/data", name="export_data", methods={"POST"})
     * @Security("is_granted('create_export')")
     *
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function export(Request $request)
    {
        $query = $this->getDefaultQuery();

        $form = $this->getToolbarForm($query, 'POST');
        $form->handleRequest($request);

        $type = $query->getType();
        if (null === $type) {
            throw $this->createNotFoundException('Missing export renderer');
        }

        $renderer = $this->export->getRendererById($type);

        if (null === $renderer) {
            throw $this->createNotFoundException('Unknown export renderer');
        }

        $entries = $this->getEntries($query);

        return $renderer->render($entries, $query);
    }

    /**
     * @param ExportQuery $query
     * @return Timesheet[]
     */
    protected function getEntries(ExportQuery $query): array
    {
        $query->getBegin()->setTime(0, 0, 0);
        $query->getEnd()->setTime(23, 59, 59);

        return $this->timesheetRepository->getTimesheetsForQuery($query);
    }

    protected function getToolbarForm(ExportQuery $query, string $method): FormInterface
    {
        return $this->createForm(ExportToolbarForm::class, $query, [
            'action' => $this->generateUrl('export', []),
            'method' => $method,
            'attr' => [
                'id' => 'export-form'
            ]
        ]);
    }
}
