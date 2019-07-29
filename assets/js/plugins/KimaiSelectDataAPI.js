/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*!
 * [KIMAI] KimaiSelectDataAPI: <select> boxes with dynamic data from API
 */

import jQuery from 'jquery';
import KimaiPlugin from "../KimaiPlugin";

export default class KimaiSelectDataAPI extends KimaiPlugin {

    constructor(selector) {
        super();
        this.selector = selector;
    }

    getId() {
        return 'select-data-api';
    }

    init() {
        this.activateApiSelects(this.selector);
    }

    activateApiSelects(selector) {
        const self = this;
        const API = this.getContainer().getPlugin('api');

        jQuery('body').on('change', selector, function(event) {
            let apiUrl = jQuery(this).attr('data-api-url').replace('-s-', jQuery(this).val());
            const targetSelect = '#' + jQuery(this).attr('data-related-select');

            // if the related target select does not exist, we do not need to load the related data
            if (jQuery(targetSelect).length === 0) {
                return;
            }

            if (jQuery(this).val() === '') {
                if (jQuery(this).attr('data-empty-url') === undefined) {
                    self._updateSelect(targetSelect, {});
                    jQuery(targetSelect).attr('disabled', 'disabled');
                    return;
                }
                apiUrl = jQuery(this).attr('data-empty-url').replace('-s-', jQuery(this).val());
            }

            jQuery(targetSelect).removeAttr('disabled');

            API.get(apiUrl, {}, function(data){
                self._updateSelect(targetSelect, data);
            });
        });
    }

    _updateSelect(selectName, data) {
        let select = jQuery(selectName);
        let emptyOption = jQuery(selectName + ' option[value=""]');

        select.find('option').remove().end().find('optgroup').remove().end();

        if (emptyOption.length !== 0) {
            select.append('<option value="">' + emptyOption.text() + '</option>');
        }

        const options = {};
        for (const apiData of data) {
            let title = apiData.parentTitle;
            if (title === null) {
                title = '__empty__';
            }
            if (!options.hasOwnProperty(title)) {
                options[title] = [];
            }
            options[title].push(apiData);
        }

        const ordered = {};
        Object.keys(options).sort().forEach(function(key) {
            ordered[key] = options[key];
        });

        let htmlOptions = '';
        let emptyOptions = '';

        for (const [key, value] of Object.entries(ordered)) {
            if (key === '__empty__') {
                for (const entity of value) {
                    emptyOptions +=  '<option value="' + entity.id + '">' + entity.name + '</option>';
                }
                continue;
            }

            htmlOptions += '<optgroup label="' + key + '">';
            for (const entity of value) {
                htmlOptions +=  '<option value="' + entity.id + '">' + entity.name + '</option>';
            }
            htmlOptions += '</optgroup>';
        }

        select.append(htmlOptions);
        select.append(emptyOptions);

        // if we don't trigger the change, the other selects won't be resetted
        select.trigger('change');

        // if the beta test kimai.theme.select_type is active, this will tell the selects to refresh
        jQuery('.selectpicker').selectpicker('refresh');
    }

}
