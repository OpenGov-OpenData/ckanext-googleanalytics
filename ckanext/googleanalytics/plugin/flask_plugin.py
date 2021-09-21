# -*- coding: utf-8 -*-
import queue

import ckan.plugins as plugins

from ckanext.googleanalytics.views import ga, ga_dataset, ga_datastore, ga_organization, ga_resource
from ckanext.googleanalytics.cli import get_commands


class GAMixinPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IClick)

    analytics_queue = queue.Queue()

    # IBlueprint

    def get_blueprint(self):
        return [ga, ga_dataset, ga_datastore, ga_organization, ga_resource]

    # IClick

    def get_commands(self):
        return get_commands()
