# -*- coding: utf-8 -*-

import hashlib
import logging
import six

from flask import Blueprint
from werkzeug.utils import import_string
from . import plugin
import ckan.logic as logic
import ckan.plugins.toolkit as tk
import ckan.views.api as api
import ckan.views.resource as resource
import ckan.views.group as group
import ckan.views.dataset as dataset
from ckanext.datastore.blueprint import dump


CONFIG_HANDLER_PATH = "googleanalytics.download_handler"

log = logging.getLogger(__name__)
ga = Blueprint("google_analytics", "google_analytics")


def action(logic_function, ver=api.API_MAX_VERSION):
    try:
        function = logic.get_action(logic_function)
        side_effect_free = getattr(function, "side_effect_free", False)
        request_data = api._get_request_data(try_url_params=side_effect_free)
        if isinstance(request_data, dict):
            id = request_data.get("id", "")
            if "q" in request_data:
                id = request_data["q"]
            if "query" in request_data:
                id = request_data[u"query"]
            _post_analytics(tk.c.user, "CKAN API Request", logic_function, "", id)
    except Exception as e:
        log.debug(e)
        pass

    return api.action(logic_function, ver)


ga.add_url_rule(
    "/api/action/<logic_function>",
    methods=["GET", "POST"],
    view_func=action,
)
ga.add_url_rule(
    u"/<int(min=3, max={0}):ver>/action/<logic_function>".format(
        api.API_MAX_VERSION
    ),
    methods=["GET", "POST"],
    view_func=action,
)


def download(id, resource_id, filename=None, package_type="dataset"):
    handler_path = tk.config.get(CONFIG_HANDLER_PATH)
    if handler_path:
        handler = import_string(handler_path, silent=True)
    else:
        handler = None
        log.warning(("Missing {} config option.").format(CONFIG_HANDLER_PATH))
    if not handler:
        log.debug("Use default CKAN callback for resource.download")
        handler = resource.download

    resource_dict = tk.get_action('resource_show')({}, {'id': resource_id})
    resource_name = resource_dict.get('name')
    package_id = resource_dict.get('package_id')
    package_dict = tk.get_action('package_show')({}, {'id': package_id})
    package_name = package_dict.get('name')
    organization_id = package_dict.get('organization').get('id')
    organization_title = package_dict.get('organization').get('title')

    try:
        resource_alias = resource_id
        if resource_name:
            resource_alias = '{} ({})'.format(resource_id, resource_name)
        _post_analytics(
            tk.c.user,
            "CKAN Resource Download Request",
            "Resource",
            "Download",
            resource_alias
        )
    except Exception:
        log.exception("Error sending resource download request (Res) to Google Analytics: "+resource_id)

    try:
        package_alias = package_name or package_id
        _post_analytics(
            tk.c.user,
            "CKAN Resource Download Request",
            "Package",
            "Download",
            package_alias
        )
    except Exception:
        log.exception("Error sending resource download request (Pkg) to Google Analytics: "+resource_id)

    try:
        organization_alias = organization_title or organization_id
        _post_analytics(
            tk.c.user,
            "CKAN Resource Download Request",
            "Organization",
            "Download",
            organization_alias
        )
    except Exception:
        log.exception("Error sending resource download request (Org) to Google Analytics: "+resource_id)

    return handler(
        package_type=package_type,
        id=id,
        resource_id=resource_id,
        filename=filename,
    )


ga.add_url_rule(
    "/dataset/<id>/resource/<resource_id>/download", view_func=download
)
ga.add_url_rule(
    "/dataset/<id>/resource/<resource_id>/download/<filename>",
    view_func=download,
)


def before_organization_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        org_id = args.get('id', '')
        org_dict = tk.get_action('organization_show')({},{'id': org_id})
        org_title = org_dict.get('title')
        _post_analytics(
            tk.c.user,
            "CKAN Organization Page View",
            "Organization",
            "View",
            org_title
        )


ga_organization = Blueprint(
    u'organization_googleanalytics',
    __name__,
    url_prefix=u'/organization',
    url_defaults={u'group_type': u'organization',
                  u'is_organization': True}
)
ga_organization.before_request(before_organization_request)
ga_organization.add_url_rule(u'/<id>', methods=[u'GET'], view_func=group.read)


def before_dataset_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        package_id = args.get('id', '')
        package_dict = tk.get_action('package_show')({}, {'id': package_id})
        org_title = package_dict.get('organization', {}).get('title')
        _post_analytics(
            tk.c.user,
            "CKAN Organization Page View",
            "Organization",
            "View",
            org_title
        )


ga_dataset = Blueprint(
    u'dataset_googleanalytics',
    __name__,
    url_prefix=u'/dataset',
    url_defaults={u'package_type': u'dataset'}
)
ga_dataset.before_request(before_dataset_request)
ga_dataset.add_url_rule(u'/<id>', view_func=dataset.read)


def before_resource_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        package_id = args.get('id', '')
        package_dict = tk.get_action('package_show')({}, {'id': package_id})
        org_title = package_dict.get('organization', {}).get('title')
        _post_analytics(
            tk.c.user,
            "CKAN Organization Page View",
            "Organization",
            "View",
            org_title
        )


ga_resource = Blueprint(
    u'resource_googleanalytics',
    __name__,
    url_prefix=u'/dataset/<id>/resource',
    url_defaults={u'package_type': u'dataset'}
)
ga_resource.before_request(before_resource_request)
ga_resource.add_url_rule(
    u'/<resource_id>',
    view_func=resource.read,
    strict_slashes=False
)


def before_datastore_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        resource_id = args.get('resource_id', '')
        _post_analytics(
            tk.c.user,
            "CKAN Resource Download Request",
            "Resource",
            "Download",
            resource_id
        )


ga_datastore = Blueprint(
    u'datastore_googleanalytics',
    __name__,
    url_prefix=u'/datastore',
)
ga_datastore.before_request(before_datastore_request)
ga_datastore.add_url_rule("/dump/<resource_id>'", view_func=dump)


def _post_analytics(
    user, event_type, request_obj_type, request_function, request_id
):
    ga_id_list = [
        tk.config.get('googleanalytics.id', None),
        tk.config.get('googleanalytics.id2', None)
    ]
    for ga_id in ga_id_list:
        if not ga_id:
            continue
        data_dict = {
            "v": 1,
            "tid": ga_id,
            "cid": hashlib.md5(six.ensure_binary(user)).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": tk.request.environ["HTTP_HOST"],
            "dp": tk.request.environ["PATH_INFO"],
            "dr": tk.request.environ.get("HTTP_REFERER", tk.request.base_url),
            "ec": event_type,
            "ea": request_obj_type + request_function,
            "el": request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)
