<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Controller;

use App\Configuration\FormConfiguration;
use App\Entity\Customer;
use App\Form\CustomerEditForm;
use App\Form\Toolbar\CustomerToolbarForm;
use App\Form\Type\CustomerType;
use App\Repository\CustomerRepository;
use App\Repository\Query\CustomerQuery;
use Doctrine\ORM\ORMException;
use Pagerfanta\Pagerfanta;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Controller used to manage customer in the admin part of the site.
 *
 * @Route(path="/admin/customer")
 * @Security("is_granted('view_customer')")
 */
class CustomerController extends AbstractController
{
    /**
     * @var CustomerRepository
     */
    private $repository;
    /**
     * @var FormConfiguration
     */
    private $configuration;

    /**
     * @param CustomerRepository $repository
     * @param FormConfiguration $configuration
     */
    public function __construct(CustomerRepository $repository, FormConfiguration $configuration)
    {
        $this->repository = $repository;
        $this->configuration = $configuration;
    }

    /**
     * @return \App\Repository\CustomerRepository
     */
    protected function getRepository()
    {
        return $this->repository;
    }

    /**
     * @Route(path="/", defaults={"page": 1}, name="admin_customer", methods={"GET"})
     * @Route(path="/page/{page}", requirements={"page": "[1-9]\d*"}, name="admin_customer_paginated", methods={"GET"})
     * @Security("is_granted('view_customer')")
     *
     * @param int $page
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function indexAction($page, Request $request)
    {
        $query = new CustomerQuery();
        $query
            ->setOrderBy('name')
            ->setPage($page)
        ;

        $form = $this->getToolbarForm($query);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            /** @var CustomerQuery $query */
            $query = $form->getData();
        }

        /* @var $entries Pagerfanta */
        $entries = $this->getRepository()->findByQuery($query);

        return $this->render('customer/index.html.twig', [
            'entries' => $entries,
            'query' => $query,
            'showFilter' => $form->isSubmitted(),
            'toolbarForm' => $form->createView(),
        ]);
    }

    /**
     * @Route(path="/create", name="admin_customer_create", methods={"GET", "POST"})
     * @Security("is_granted('create_customer')")
     *
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function createAction(Request $request)
    {
        $customer = new Customer();
        $customer->setCountry($this->configuration->getCustomerDefaultCountry());
        $customer->setCurrency($this->configuration->getCustomerDefaultCurrency());
        $customer->setTimezone($this->configuration->getCustomerDefaultTimezone());

        return $this->renderCustomerForm($customer, $request);
    }

    /**
     * @Route(path="/{id}/edit", name="admin_customer_edit", methods={"GET", "POST"})
     * @Security("is_granted('edit', customer)")
     *
     * @param Customer $customer
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function editAction(Customer $customer, Request $request)
    {
        return $this->renderCustomerForm($customer, $request);
    }

    /**
     * @Route(path="/{id}/delete", name="admin_customer_delete", methods={"GET", "POST"})
     * @Security("is_granted('delete', customer)")
     *
     * @param Customer $customer
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function deleteAction(Customer $customer, Request $request)
    {
        $stats = $this->getRepository()->getCustomerStatistics($customer);

        $deleteForm = $this->createFormBuilder(null, [
                'attr' => [
                    'data-form-event' => 'kimai.customerUpdate kimai.customerDelete',
                    'data-msg-success' => 'action.delete.success',
                    'data-msg-error' => 'action.delete.error',
                ]
            ])
            ->add('customer', CustomerType::class, [
                'label' => 'label.customer',
                'query_builder' => function (CustomerRepository $repo) use ($customer) {
                    $query = new CustomerQuery();
                    $query
                        ->setResultType(CustomerQuery::RESULT_TYPE_QUERYBUILDER)
                        ->addIgnoredEntity($customer);

                    return $repo->findByQuery($query);
                },
                'required' => false,
            ])
            ->setAction($this->generateUrl('admin_customer_delete', ['id' => $customer->getId()]))
            ->setMethod('POST')
            ->getForm();

        $deleteForm->handleRequest($request);

        if ($deleteForm->isSubmitted() && $deleteForm->isValid()) {
            try {
                $this->getRepository()->deleteCustomer($customer, $deleteForm->get('customer')->getData());
                $this->flashSuccess('action.delete.success');
            } catch (ORMException $ex) {
                $this->flashError('action.delete.error', ['%reason%' => $ex->getMessage()]);
            }

            return $this->redirectToRoute('admin_customer');
        }

        return $this->render('customer/delete.html.twig', [
            'customer' => $customer,
            'stats' => $stats,
            'form' => $deleteForm->createView(),
        ]);
    }

    /**
     * @param Customer $customer
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    protected function renderCustomerForm(Customer $customer, Request $request)
    {
        $editForm = $this->createEditForm($customer);

        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($customer);
            $entityManager->flush();

            $this->flashSuccess('action.update.success');

            return $this->redirectToRoute('admin_customer');
        }

        return $this->render('customer/edit.html.twig', [
            'customer' => $customer,
            'form' => $editForm->createView()
        ]);
    }

    /**
     * @param CustomerQuery $query
     * @return \Symfony\Component\Form\FormInterface
     */
    protected function getToolbarForm(CustomerQuery $query)
    {
        return $this->createForm(CustomerToolbarForm::class, $query, [
            'action' => $this->generateUrl('admin_customer', [
                'page' => $query->getPage(),
            ]),
            'method' => 'GET',
        ]);
    }

    /**
     * @param Customer $customer
     * @return \Symfony\Component\Form\FormInterface
     */
    private function createEditForm(Customer $customer)
    {
        if ($customer->getId() === null) {
            $url = $this->generateUrl('admin_customer_create');
        } else {
            $url = $this->generateUrl('admin_customer_edit', ['id' => $customer->getId()]);
        }

        return $this->createForm(CustomerEditForm::class, $customer, [
            'action' => $url,
            'method' => 'POST'
        ]);
    }
}
