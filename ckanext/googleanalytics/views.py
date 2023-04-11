# -*- coding: utf-8 -*-

import hashlib
import logging
import six

from flask import Blueprint

import ckan.plugins.toolkit as tk
import ckan.views.api as api
import ckan.views.resource as resource
import ckan.views.group as group
import ckan.views.dataset as dataset
from ckanext.datastore.blueprint import dump

from ckan.common import g
from ckan.plugins import PluginImplementations

from ckanext.googleanalytics import utils, config, interfaces

CONFIG_HANDLER_PATH = "googleanalytics.download_handler"

log = logging.getLogger(__name__)
ga = Blueprint("google_analytics", "google_analytics")
_ = tk._


def action(logic_function, ver=api.API_MAX_VERSION):
    try:
        function = tk.get_action(logic_function)
        side_effect_free = getattr(function, "side_effect_free", False)
        request_data = api._get_request_data(try_url_params=side_effect_free)
        if isinstance(request_data, dict):
            id = request_data.get("id", "")
            if "q" in request_data:
                id = request_data["q"]
            if "query" in request_data:
                id = request_data[u"query"]
            _post_analytics(g.user, utils.EVENT_API, logic_function, "", id, request_data)
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
    "/api/<int(min=3, max={0}):ver>/action/<logic_function>".format(
        api.API_MAX_VERSION
    ),
    methods=["GET", "POST"],
    view_func=action,
)


def download(id, resource_id, filename=None, package_type="dataset"):
    handler = config.download_handler()
    if not handler:
        log.debug("Use default CKAN callback for resource.download")
        handler = resource.download

    try:
        resource_dict = tk.get_action('resource_show')({}, {'id': resource_id})
        resource_name = resource_dict.get('name')
    except tk.ValidationError as error:
        return tk.abort(400, error.message)
    except (tk.ObjectNotFound, tk.NotAuthorized):
        return tk.abort(404, _('Resource not found'))

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
        log.debug("Error sending resource download request to Google Analytics: " + resource_id)

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

        if org_id == 'new':
            return

        try:
            org_dict = tk.get_action('organization_show')({}, {'id': org_id})
            org_title = org_dict.get('title')
            _post_analytics(
                tk.c.user,
                "CKAN Organization Page View",
                "Organization",
                "View",
                org_title
            )
        except Exception as e:
            log.debug(e)


ga_organization = Blueprint(
    u'organization_googleanalytics',
    __name__,
    url_prefix=u'/organization',
    url_defaults={u'group_type': u'organization',
                  u'is_organization': True}
)
ga_organization.before_request(before_organization_request)
ga_organization.add_url_rule(u'/new', view_func=group.CreateGroupView.as_view('new'))
ga_organization.add_url_rule(u'/<id>', methods=[u'GET'], view_func=group.read)


def before_dataset_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        package_id = args.get('id', '')

        if package_id == 'new':
            return

        try:
            package_dict = tk.get_action('package_show')({}, {'id': package_id})
            org_title = package_dict.get('organization', {}).get('title')
            _post_analytics(
                tk.c.user,
                "CKAN Organization Page View",
                "Organization",
                "View",
                org_title
            )
        except Exception as e:
            log.debug(e)


ga_dataset = Blueprint(
    u'dataset_googleanalytics',
    __name__,
    url_prefix=u'/dataset',
    url_defaults={u'package_type': u'dataset'}
)
ga_dataset.before_request(before_dataset_request)
ga_dataset.add_url_rule(u'/new', view_func=dataset.CreateView.as_view('new'))
ga_dataset.add_url_rule(u'/<id>', methods=[u'GET'], view_func=dataset.read)


def before_resource_request():
    if tk.request.method == 'GET':
        args = tk.request.view_args
        package_id = args.get('id', '')
        resource_id = args.get('resource_id', '')

        if resource_id == 'new':
            return

        try:
            package_dict = tk.get_action('package_show')({}, {'id': package_id})
            org_title = package_dict.get('organization', {}).get('title')
            _post_analytics(
                tk.c.user,
                "CKAN Organization Page View",
                "Organization",
                "View",
                org_title
            )
        except Exception as e:
            log.debug(e)


ga_resource = Blueprint(
    u'resource_googleanalytics',
    __name__,
    url_prefix=u'/dataset/<id>/resource',
    url_defaults={u'package_type': u'dataset'}
)
ga_resource.before_request(before_resource_request)
ga_resource.add_url_rule(u'/new', view_func=resource.CreateView.as_view('new'))
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
ga_datastore.add_url_rule('/dump/<resource_id>', view_func=dump)


def _post_analytics(
        user, event_type,
        request_obj_type, request_function,
        request_id, request_payload=None
):

    from ckanext.googleanalytics.plugin import GoogleAnalyticsPlugin

    if config.tracking_id():
        if config.measurement_protocol_client_id() and event_type == utils.EVENT_API:
            data_dict = utils.MeasurementProtocolData({
                "event": event_type,
                "object": request_obj_type,
                "function": request_function,
                "id": request_id,
                "payload": request_payload,
            })
        else:
            data_dict = utils.UniversalAnalyticsData({
                "v": 1,
                "tid": config.tracking_id(),
                "cid": hashlib.md5(six.ensure_binary(tk.c.user)).hexdigest(),
                # customer id should be obfuscated
                "t": "event",
                "dh": tk.request.environ["HTTP_HOST"],
                "dp": tk.request.environ["PATH_INFO"],
                "dr": tk.request.environ.get("HTTP_REFERER", ""),
                "ec": event_type,
                "ea": request_obj_type + request_function,
                "el": request_id,
            })

        for p in PluginImplementations(interfaces.IGoogleAnalytics):
            if p.googleanalytics_skip_event(data_dict):
                return

        GoogleAnalyticsPlugin.analytics_queue.put(data_dict)
