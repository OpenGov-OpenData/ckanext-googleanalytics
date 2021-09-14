# -*- coding: utf-8 -*-
import queue

import ckan.plugins as plugins

from ckanext.googleanalytics.views import ga, dataset_b, datastore_b, organization_b
from ckanext.googleanalytics.cli import get_commands


class GAMixinPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IClick)

    analytics_queue = queue.Queue()

    # IBlueprint

    def get_blueprint(self):
        return [ga, dataset_b, datastore_b, organization_b]

    # IClick

    def get_commands(self):
        return get_commands()
