# -*- coding: utf-8 -*-

import hashlib
import logging
import six
from ckan.views import dataset
from ckan.views.group import read
from ckanext.datastore.blueprint import dump

from flask import Blueprint
from werkzeug.utils import import_string
from . import plugin
import ckan.logic as logic
import ckan.plugins.toolkit as tk
import ckan.views.api as api


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
            post_analytics("CKAN API Request", logic_function, "API Request", id)
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

    resource = tk.get_action('resource_show')({}, {'id': resource_id})
    resource_name = resource.get('name')
    package_id = resource.get('package_id')
    package = tk.get_action('package_show')({}, {'id': package_id})
    package_name = package.get('name')
    organization_id = package.get('organization').get('id')
    organization_title = package.get('organization').get('title')

    try:
        resource_alias = resource_id
        if resource_name:
            resource_alias = '{} ({})'.format(resource_id, resource_name)
        post_analytics("Resource", "Download", "CKAN Resource Download Request", resource_alias)
    except Exception:
        log.exception("Error sending resource download request (Res) to Google Analytics: "+resource_id)

    try:
        package_alias = package_name or package_id
        post_analytics("Package", "Download", "CKAN Resource Download Request", package_alias)
    except Exception:
        log.exception("Error sending resource download request (Pkg) to Google Analytics: "+resource_id)

    try:
        organization_alias = organization_title or organization_id
        post_analytics("Organization", "Download", "CKAN Resource Download Request", organization_alias)
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


def post_analytics(request_obj_type, request_function, event_type, request_id=''):
    args = tk.request.view_args
    r_id = args.get('id', '')
    try:
        package = tk.get_action('package_show')({}, {'id': r_id})
        org_id = package.get('organization').get('title')
    except Exception:
        log.debug('Dataset not found: ' + r_id)
        org_id = ''
    g_ids = {
        tk.config.get('googleanalytics.id', None),
        tk.config.get('googleanalytics.id2', None),
    }
    for g_id in g_ids:
        if not g_id:
            continue
        data_dict = {
            "v": 1,
            "tid": g_id,
            "cid": hashlib.md5(six.ensure_binary(tk.c.user)).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": tk.request.environ["HTTP_HOST"],
            "dp": tk.request.environ["PATH_INFO"],
            "dr": tk.request.environ.get("HTTP_REFERER", tk.request.base_url),
            "ec": event_type,
            "ea": '{} {}'.format(request_obj_type, request_function),
            "el": org_id or request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)


def before_dataset_request():
    if tk.request.method == 'GET':
        post_analytics("Organization", "View", "CKAN Organization Page View")


def before_datastore_request():
    if tk.request.method == 'GET':
        post_analytics("Resource", "Download", "CKAN Resource Download Request")


def before_organization_request():
    if tk.request.method == 'GET':
        post_analytics("Organization", "View", "CKAN Organization Page View")


dataset_b = Blueprint(
    u'dataset_googleanalytics',
    __name__,
    url_prefix=u'/dataset',
    url_defaults={u'package_type': u'dataset'}
)
dataset_b.before_request(before_dataset_request)
dataset_b.add_url_rule(u'/<id>', view_func=dataset.read)
dataset_b.add_url_rule(u'/resources/<id>', view_func=dataset.resources)


datastore_b = Blueprint(
    u'datastore_googleanalytics',
    __name__,
    url_prefix=u'/datastore',
)
datastore_b.before_request(before_datastore_request)
datastore_b.add_url_rule("/dump/<resource_id>'", view_func=dump)


organization_b = Blueprint(
    u'organization_googleanalytics',
    __name__,
    url_prefix=u'/organization',
    url_defaults={u'group_type': u'organization',
                  u'is_organization': True}
)
organization_b.before_request(before_organization_request)
organization_b.add_url_rule(u'/<id>', methods=[u'GET'], view_func=read)
