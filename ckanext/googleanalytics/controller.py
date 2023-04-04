from __future__ import absolute_import

import logging
from ckan.lib.base import BaseController, c, render, request
from . import dbutil

import hashlib
from . import plugin

from paste.util.multidict import MultiDict

from ckan.controllers.api import ApiController
from ckan.controllers.organization import OrganizationController
from ckan.controllers.package import PackageController
from ckanext.datastore.controller import DatastoreController

import ckan.plugins.toolkit as tk
from ckanext.googleanalytics import config


log = logging.getLogger("ckanext.googleanalytics")


class GAController(BaseController):
    def view(self):
        # get package objects corresponding to popular GA content
        c.top_resources = dbutil.get_top_resources(limit=10)
        return render("summary.html")


class GAApiController(ApiController):
    # intercept API calls to record via google analytics
    def _post_analytics(
        self, user, request_obj_type, request_function, request_id
    ):
        data_dict = {
            "v": 1,
            "tid": config.tracking_id(),
            "cid": hashlib.md5(user).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": c.environ["HTTP_HOST"],
            "dp": c.environ["PATH_INFO"],
            "dr": c.environ.get("HTTP_REFERER", ""),
            "ec": "CKAN API Request",
            "ea": request_obj_type + request_function,
            "el": request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)

    def action(self, logic_function, ver=None):
        try:
            function = tk.get_action(logic_function)
            side_effect_free = getattr(function, "side_effect_free", False)
            request_data = self._get_request_data(
                try_url_params=side_effect_free
            )
            if isinstance(request_data, dict):
                id = request_data.get("id", "")
                if "q" in request_data:
                    id = request_data["q"]
                if "query" in request_data:
                    id = request_data["query"]
                self._post_analytics(c.user, logic_function, "", id)
        except Exception as e:
            log.debug(e)
            pass
        return ApiController.action(self, logic_function, ver)

    def list(self, ver=None, register=None, subregister=None, id=None):
        self._post_analytics(
            c.user,
            register + ("_" + str(subregister) if subregister else ""),
            "list",
            id,
        )
        return ApiController.list(self, ver, register, subregister, id)

    def show(
        self, ver=None, register=None, subregister=None, id=None, id2=None
    ):
        self._post_analytics(
            c.user,
            register + ("_" + str(subregister) if subregister else ""),
            "show",
            id,
        )
        return ApiController.show(self, ver, register, subregister, id, id2)

    def update(
        self, ver=None, register=None, subregister=None, id=None, id2=None
    ):
        self._post_analytics(
            c.user,
            register + ("_" + str(subregister) if subregister else ""),
            "update",
            id,
        )
        return ApiController.update(self, ver, register, subregister, id, id2)

    def delete(
        self, ver=None, register=None, subregister=None, id=None, id2=None
    ):
        self._post_analytics(
            c.user,
            register + ("_" + str(subregister) if subregister else ""),
            "delete",
            id,
        )
        return ApiController.delete(self, ver, register, subregister, id, id2)

    def search(self, ver=None, register=None):
        id = None
        try:
            params = MultiDict(self._get_search_params(request.params))
            if "q" in list(params.keys()):
                id = params["q"]
            if "query" in list(params.keys()):
                id = params["query"]
        except ValueError as e:
            log.debug(str(e))
            pass
        self._post_analytics(c.user, register, "search", id)

        return ApiController.search(self, ver, register)


class GAOrganizationController(OrganizationController):
    def _post_analytics(self, user, request_obj_type, request_function, request_id):
        data_dict = {
            "v": 1,
            "tid": config.tracking_id(),
            "cid": hashlib.md5(user).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": c.environ['HTTP_HOST'],
            "dp": c.environ['PATH_INFO'],
            "dr": c.environ.get('HTTP_REFERER', ''),
            "ec": "CKAN Organization Page View",
            "ea": request_obj_type + request_function,
            "el": request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)

    def read(self, id, limit=20):
        # We do not want to perform read operation on organization id "new",
        # where it results in a NotFound error
        if id == "new":
            return OrganizationController.new(self)
        try:
            org = tk.get_action('organization_show')({}, {'id': id})
            org_title = org.get('title')
            self._post_analytics(c.user, "Organization", "View", org_title)
        except Exception as e:
            log.debug(e)
        return OrganizationController.read(self, id, limit=20)


class GAPackageController(PackageController):
    def _post_analytics(self, user, request_obj_type, request_function, request_id):
        data_dict = {
            "v": 1,
            "tid": config.tracking_id(),
            "cid": hashlib.md5(user).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": c.environ['HTTP_HOST'],
            "dp": c.environ['PATH_INFO'],
            "dr": c.environ.get('HTTP_REFERER', ''),
            "ec": "CKAN Organization Page View",
            "ea": request_obj_type + request_function,
            "el": request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)

    # This function is called everytime we access a dataset including
    # the dataset "new" when creating a new datasets
    def read(self, id):
        # We do not want to perform read operation on package id "new",
        # where it results in the package not being found
        if id == "new":
            return PackageController.new(self)
        try:
            org_id = self.get_package_org_id(id)
            if org_id:
                self._post_analytics(c.user, "Organization", "View", org_id)
        except Exception as e:
            log.debug(e)
        return PackageController.read(self, id)

    def resource_read(self, id, resource_id):
        try:
            org_id = self.get_package_org_id(id)
            if org_id:
                self._post_analytics(c.user, "Organization", "View", org_id)
        except Exception as e:
            log.debug(e)
        return PackageController.resource_read(self, id, resource_id)

    def get_package_org_id(self, package_id):
        org_id = ''
        try:
            package = tk.get_action('package_show')({}, {'id': package_id})
            org_id = package.get('organization', {}).get('title')
        except Exception as e:
            log.debug(e)
        return org_id


class GADatastoreController(DatastoreController):
    def _post_analytics(
        self, user, request_obj_type, request_function, request_id
    ):
        data_dict = {
            "v": 1,
            "tid": config.tracking_id(),
            "cid": hashlib.md5(user).hexdigest(),
            # customer id should be obfuscated
            "t": "event",
            "dh": c.environ['HTTP_HOST'],
            "dp": c.environ['PATH_INFO'],
            "dr": c.environ.get('HTTP_REFERER', ''),
            "ec": "CKAN Resource Download Request",
            "ea": request_obj_type + request_function,
            "el": request_id,
        }
        plugin.GoogleAnalyticsPlugin.analytics_queue.put(data_dict)

    def dump(self, resource_id):
        self._post_analytics(c.user, "Resource", "Download", resource_id)
        return DatastoreController.dump(self, resource_id)
