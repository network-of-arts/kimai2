<?php

declare(strict_types=1);

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\API;

use App\Entity\Customer;
use App\Form\API\CustomerApiEditForm;
use App\Repository\CustomerRepository;
use App\Repository\Query\CustomerQuery;
use FOS\RestBundle\Controller\Annotations as Rest;
use FOS\RestBundle\Controller\Annotations\RouteResource;
use FOS\RestBundle\Request\ParamFetcherInterface;
use FOS\RestBundle\View\View;
use FOS\RestBundle\View\ViewHandlerInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Swagger\Annotations as SWG;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * @RouteResource("Customer")
 *
 * @Security("is_granted('ROLE_USER')")
 */
class CustomerController extends BaseApiController
{
    /**
     * @var CustomerRepository
     */
    protected $repository;
    /**
     * @var ViewHandlerInterface
     */
    protected $viewHandler;

    public function __construct(ViewHandlerInterface $viewHandler, CustomerRepository $repository)
    {
        $this->viewHandler = $viewHandler;
        $this->repository = $repository;
    }

    /**
     * Returns a collection of customers
     *
     * @SWG\Response(
     *      response=200,
     *      description="Returns a collection of customer entities",
     *      @SWG\Schema(
     *          type="array",
     *          @SWG\Items(ref="#/definitions/CustomerCollection")
     *      )
     * )
     * @Rest\QueryParam(name="visible", requirements="\d+", strict=true, nullable=true, description="Visibility status to filter activities (1=visible, 2=hidden, 3=both)")
     * @Rest\QueryParam(name="order", requirements="ASC|DESC", strict=true, nullable=true, description="The result order. Allowed values: ASC, DESC (default: ASC)")
     * @Rest\QueryParam(name="orderBy", requirements="id|name", strict=true, nullable=true, description="The field by which results will be ordered. Allowed values: id, name (default: name)")
     *
     * @return Response
     */
    public function cgetAction(ParamFetcherInterface $paramFetcher)
    {
        $query = new CustomerQuery();

        if (null !== ($order = $paramFetcher->get('order'))) {
            $query->setOrder($order);
        }

        if (null !== ($orderBy = $paramFetcher->get('orderBy'))) {
            $query->setOrderBy($orderBy);
        }

        if (null !== ($visible = $paramFetcher->get('visible'))) {
            $query->setVisibility($visible);
        }

        $data = $this->repository->getCustomersForQuery($query);
        $view = new View($data, 200);
        $view->getContext()->setGroups(['Default', 'Collection', 'Customer']);

        return $this->viewHandler->handle($view);
    }

    /**
     * Returns one customer
     *
     * @SWG\Response(
     *      response=200,
     *      description="Returns one customer entity",
     *      @SWG\Schema(ref="#/definitions/CustomerEntity"),
     * )
     *
     * @param int $id
     * @return Response
     */
    public function getAction($id)
    {
        /** @var Customer $data */
        $data = $this->repository->find($id);

        if (null === $data) {
            throw new NotFoundException();
        }

        $view = new View($data, 200);
        $view->getContext()->setGroups(['Default', 'Entity', 'Customer']);

        return $this->viewHandler->handle($view);
    }

    /**
     * Creates a new customer
     *
     * @SWG\Post(
     *      description="Creates a new customer and returns it afterwards",
     *      @SWG\Response(
     *          response=200,
     *          description="Returns the new created customer",
     *          @SWG\Schema(ref="#/definitions/CustomerEntity"),
     *      )
     * )
     * @SWG\Parameter(
     *      name="body",
     *      in="body",
     *      required=true,
     *      @SWG\Schema(ref="#/definitions/CustomerEditForm")
     * )
     *
     * @param Request $request
     * @return Response
     * @throws \App\Repository\RepositoryException
     * @throws \Doctrine\ORM\ORMException
     * @throws \Doctrine\ORM\OptimisticLockException
     */
    public function postAction(Request $request)
    {
        if (!$this->isGranted('create_customer')) {
            throw new AccessDeniedHttpException('User cannot create customers');
        }

        $customer = new Customer();

        $form = $this->createForm(CustomerApiEditForm::class, $customer);

        $form->submit($request->request->all());

        if ($form->isValid()) {
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($customer);
            $entityManager->flush();

            $view = new View($customer, 200);
            $view->getContext()->setGroups(['Default', 'Entity', 'Customer']);

            return $this->viewHandler->handle($view);
        }

        $view = new View($form);
        $view->getContext()->setGroups(['Default', 'Entity', 'Customer']);

        return $this->viewHandler->handle($view);
    }

    /**
     * Update an existing customer
     *
     * @SWG\Patch(
     *      description="Update an existing customer, you can pass all or just a subset of all attributes",
     *      @SWG\Response(
     *          response=200,
     *          description="Returns the updated customer",
     *          @SWG\Schema(ref="#/definitions/CustomerEntity")
     *      )
     * )
     * @SWG\Parameter(
     *      name="body",
     *      in="body",
     *      required=true,
     *      @SWG\Schema(ref="#/definitions/CustomerEditForm")
     * )
     * @SWG\Parameter(
     *      name="id",
     *      in="path",
     *      type="integer",
     *      description="Customer ID to update",
     *      required=true,
     * )
     *
     * @param Request $request
     * @param string $id
     * @return Response
     */
    public function patchAction(Request $request, string $id)
    {
        $customer = $this->repository->find($id);

        if (null === $customer) {
            throw new NotFoundException();
        }

        if (!$this->isGranted('edit', $customer)) {
            throw new AccessDeniedHttpException('User cannot update customer');
        }

        $form = $this->createForm(CustomerApiEditForm::class, $customer);

        $form->setData($customer);
        $form->submit($request->request->all(), false);

        if (false === $form->isValid()) {
            $view = new View($form, Response::HTTP_OK);
            $view->getContext()->setGroups(['Default', 'Entity', 'Customer']);

            return $this->viewHandler->handle($view);
        }

        $entityManager = $this->getDoctrine()->getManager();
        $entityManager->persist($customer);
        $entityManager->flush();

        $view = new View($customer, Response::HTTP_OK);
        $view->getContext()->setGroups(['Default', 'Entity', 'Customer']);

        return $this->viewHandler->handle($view);
    }
}
