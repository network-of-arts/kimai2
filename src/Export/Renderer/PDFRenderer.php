<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Export\Renderer;

use App\Configuration\ExportConfiguration;
use App\Entity\Timesheet;
use App\Export\Base\PDFRenderer as BasePDFRenderer;
use App\Export\RendererInterface;
use App\Repository\Query\TimesheetQuery;
use App\Timesheet\UserDateTimeFactory;
use App\Utils\HtmlToPdfConverter;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Twig\Environment;

final class PDFRenderer extends BasePDFRenderer implements RendererInterface
{
    use RendererTrait;

    /**
     * @var Environment
     */
    protected $twig;
    /**
     * @var UserDateTimeFactory
     */
    protected $dateTime;
    /**
     * @var HtmlToPdfConverter
     */
    protected $converter;
    /**
     * @var \App\Configuration\ExportConfiguration
     */
    private $exportConfiguration;

    /**
     * @param Environment $twig
     * @param UserDateTimeFactory $dateTime
     * @param HtmlToPdfConverter $converter
     */
    public function __construct(
        Environment $twig,
        UserDateTimeFactory $dateTime,
        HtmlToPdfConverter $converter,
        ExportConfiguration $exportConfiguration
    ) {
        $this->twig = $twig;
        $this->dateTime = $dateTime;
        $this->converter = $converter;
        $this->exportConfiguration = $exportConfiguration;
    }

    /**
     * @param Timesheet[] $timesheets
     * @param TimesheetQuery $query
     * @return Response
     * @throws \Twig\Error\LoaderError
     * @throws \Twig\Error\RuntimeError
     * @throws \Twig\Error\SyntaxError
     */
    public function render(array $timesheets, TimesheetQuery $query): Response
    {
        $content = $this->twig->render('export/renderer/pdf.html.twig', [
            'entries' => $timesheets,
            'query' => $query,
            'now' => $this->dateTime->createDateTime(),
            'summaries' => $this->calculateSummary($timesheets),
            'user_summary' => $this->calculateUserSummary($timesheets),
            'display_cost' => $this->exportConfiguration->doDisplayCostOnPdf(),
        ]);

        $content = $this->converter->convertToPdf($content);

        $response = new Response($content);

        $disposition =
            $response->headers->makeDisposition(
                ResponseHeaderBag::DISPOSITION_INLINE,
                'kimai-export.pdf'
            );

        $response->headers->set('Content-Type', 'application/pdf');
        $response->headers->set('Content-Disposition', $disposition);

        return $response;
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return 'pdf';
    }

    /**
     * @return string
     */
    public function getIcon(): string
    {
        return 'pdf';
    }

    /**
     * @return string
     */
    public function getTitle(): string
    {
        return 'pdf';
    }
}
