/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*!
 * [KIMAI] KimaiDatatable: handles functionality for the datatable
 */

import jQuery from 'jquery';
import KimaiPlugin from "../KimaiPlugin";

export default class KimaiDatatable extends KimaiPlugin {

    constructor(selector) {
        super();
        this.selector = selector;
    }

    getId() {
        return 'datatable';
    }

    init() {
        const dataTable = document.querySelector(this.selector);

        // not every page contains a dataTable
        if (dataTable === null) {
            return;
        }

        const attributes = dataTable.dataset;
        const events = attributes['reloadEvent'];

        if (events === undefined) {
            return;
        }

        const self = this;
        const handle = function() { self.reloadDatatable(); };

        for (let eventName of events.split(' ')) {
            document.addEventListener(eventName, handle);
        }
    }

    reloadDatatable() {
        // FIXME remove query
        const durations = this.getContainer().getPlugin('timesheet-duration');
        const form = jQuery('.toolbar form');
        let loading = '<div class="overlay"><i class="fas fa-sync fa-spin"></i></div>';
        jQuery('section.content').append(loading);

        // remove the empty fields to prevent errors
        let formData = jQuery('.toolbar form :input')
            .filter(function(index, element) {
                return jQuery(element).val() != '';
            })
            .serialize();

        jQuery.ajax({
            url: form.attr('action'),
            type: form.attr('method'),
            data: formData,
            success: function(html) {
                jQuery('section.content').replaceWith(
                    jQuery(html).find('section.content')
                );
                durations.updateRecords();
            },
            error: function(xhr, err) {
                form.submit();
            }
        });

    }
}
