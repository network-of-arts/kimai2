<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Form;

use App\Entity\Customer;
use App\Entity\Project;
use App\Form\Type\ColorPickerType;
use App\Form\Type\CustomerType;
use App\Form\Type\FixedRateType;
use App\Form\Type\HourlyRateType;
use App\Form\Type\YesNoType;
use App\Repository\CustomerRepository;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Defines the form used to edit Projects.
 */
class ProjectEditForm extends AbstractType
{
    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $customer = null;
        $currency = false;
        $id = null;

        if (isset($options['data'])) {
            /** @var Project $entry */
            $entry = $options['data'];
            $id = $entry->getId();

            if ($id !== null) {
                $customer = $entry->getCustomer();
                $currency = $customer->getCurrency();
            }
        }

        $builder
            ->add('name', TextType::class, [
                'label' => 'label.name',
                'attr' => [
                    'autofocus' => 'autofocus'
                ],
            ])
            ->add('comment', TextareaType::class, [
                'label' => 'label.comment',
                'required' => false,
            ])
            ->add('orderNumber', TextType::class, [
                'label' => 'label.orderNumber',
                'required' => false,
            ])
            ->add('customer', CustomerType::class, [
                'query_builder' => function (CustomerRepository $repo) use ($customer) {
                    return $repo->builderForEntityType($customer);
                },
            ])
            ->add('color', ColorPickerType::class)
            ->add('fixedRate', FixedRateType::class, [
                'currency' => $currency,
            ])
            ->add('hourlyRate', HourlyRateType::class, [
                'currency' => $currency,
            ])
            ->add('budget', MoneyType::class, [
                'label' => 'label.budget',
                'required' => false,
                'currency' => $currency,
            ])
            ->add('visible', YesNoType::class, [
                'label' => 'label.visible',
            ])
        ;

        if (null === $id && $options['create_more']) {
            $builder->add('create_more', CheckboxType::class, [
                'label' => 'label.create_more',
                'required' => false,
                'mapped' => false,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'data_class' => Project::class,
            'csrf_protection' => true,
            'csrf_field_name' => '_token',
            'csrf_token_id' => 'admin_project_edit',
            'currency' => Customer::DEFAULT_CURRENCY,
            'create_more' => false,
            'attr' => [
                'data-form-event' => 'kimai.projectUpdate'
            ],
        ]);
    }
}
