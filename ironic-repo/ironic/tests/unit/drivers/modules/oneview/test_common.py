# -*- encoding: utf-8 -*-
#
# Copyright 2015 Hewlett Packard Development Company, LP
# Copyright 2015 Universidade Federal de Campina Grande
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
from oslo_utils import importutils

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers.modules.oneview import common
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils

oneview_states = importutils.try_import('oneview_client.states')


class OneViewCommonTestCase(db_base.DbTestCase):

    def setUp(self):
        super(OneViewCommonTestCase, self).setUp()
        self.node = obj_utils.create_test_node(
            self.context, driver='fake_oneview',
            properties=db_utils.get_test_oneview_properties(),
            driver_info=db_utils.get_test_oneview_driver_info(),
        )
        self.config(manager_url='https://1.2.3.4', group='oneview')
        self.config(username='user', group='oneview')
        self.config(password='password', group='oneview')
        mgr_utils.mock_the_extension_manager(driver="fake_oneview")

    def test_verify_node_info(self):
        common.verify_node_info(self.node)

    def test_verify_node_info_missing_node_properties(self):
        self.node.properties = {
            "cpu_arch": "x86_64",
            "cpus": "8",
            "local_gb": "10",
            "memory_mb": "4096",
            "capabilities": ("enclosure_group_uri:fake_eg_uri,"
                             "server_profile_template_uri:fake_spt_uri")
        }
        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "server_hardware_type_uri"):
            common.verify_node_info(self.node)

    def test_verify_node_info_missing_node_driver_info(self):
        self.node.driver_info = {}

        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "server_hardware_uri"):
            common.verify_node_info(self.node)

    def test_verify_node_info_missing_spt(self):
        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = ("server_hardware_type_uri:fake_sht_uri,"
                                      "enclosure_group_uri:fake_eg_uri")

        self.node.properties = properties
        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "server_profile_template_uri"):
            common.verify_node_info(self.node)

    def test_verify_node_info_missing_sh(self):
        driver_info = db_utils.get_test_oneview_driver_info()

        del driver_info["server_hardware_uri"]
        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = (
            "server_hardware_type_uri:fake_sht_uri,"
            "enclosure_group_uri:fake_eg_uri,"
            "server_profile_template_uri:fake_spt_uri"
        )

        self.node.properties = properties
        self.node.driver_info = driver_info
        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "server_hardware_uri"):
            common.verify_node_info(self.node)

    def test_verify_node_info_missing_sht(self):
        driver_info = db_utils.get_test_oneview_driver_info()
        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = (
            "enclosure_group_uri:fake_eg_uri,"
            "server_profile_template_uri:fake_spt_uri"
        )

        self.node.properties = properties
        self.node.driver_info = driver_info
        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "server_hardware_type_uri"):
            common.verify_node_info(self.node)

    def test_get_oneview_info(self):
        complete_node = self.node
        expected_node_info = {
            'server_hardware_uri': 'fake_sh_uri',
            'server_hardware_type_uri': 'fake_sht_uri',
            'enclosure_group_uri': 'fake_eg_uri',
            'server_profile_template_uri': 'fake_spt_uri',
        }

        self.assertEqual(
            expected_node_info,
            common.get_oneview_info(complete_node)
        )

    def test_get_oneview_info_missing_spt(self):
        driver_info = db_utils.get_test_oneview_driver_info()

        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = ("server_hardware_type_uri:fake_sht_uri,"
                                      "enclosure_group_uri:fake_eg_uri")

        self.node.driver_info = driver_info
        self.node.properties = properties

        incomplete_node = self.node
        expected_node_info = {
            'server_hardware_uri': 'fake_sh_uri',
            'server_hardware_type_uri': 'fake_sht_uri',
            'enclosure_group_uri': 'fake_eg_uri',
            'server_profile_template_uri': None,
        }

        self.assertEqual(
            expected_node_info,
            common.get_oneview_info(incomplete_node)
        )

    def test_get_oneview_info_missing_sh(self):
        driver_info = db_utils.get_test_oneview_driver_info()

        del driver_info["server_hardware_uri"]
        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = (
            "server_hardware_type_uri:fake_sht_uri,"
            "enclosure_group_uri:fake_eg_uri,"
            "server_profile_template_uri:fake_spt_uri"
        )

        self.node.driver_info = driver_info
        self.node.properties = properties

        incomplete_node = self.node
        expected_node_info = {
            'server_hardware_uri': None,
            'server_hardware_type_uri': 'fake_sht_uri',
            'enclosure_group_uri': 'fake_eg_uri',
            'server_profile_template_uri': 'fake_spt_uri',
        }

        self.assertEqual(
            expected_node_info,
            common.get_oneview_info(incomplete_node)
        )

    # TODO(gabriel-bezerra): Remove this after Mitaka
    @mock.patch.object(common, 'LOG', autospec=True)
    def test_deprecated_spt_in_driver_info(self, log_mock):
        # the current model has server_profile_template_uri in
        # properties/capabilities instead of driver_info

        driver_info = db_utils.get_test_oneview_driver_info()
        driver_info['server_profile_template_uri'] = 'fake_spt_uri'

        properties = db_utils.get_test_oneview_properties()
        properties["capabilities"] = ("server_hardware_type_uri:fake_sht_uri,"
                                      "enclosure_group_uri:fake_eg_uri")

        self.node.driver_info = driver_info
        self.node.properties = properties

        deprecated_node = self.node
        expected_node_info = {
            'server_hardware_uri': 'fake_sh_uri',
            'server_hardware_type_uri': 'fake_sht_uri',
            'enclosure_group_uri': 'fake_eg_uri',
            'server_profile_template_uri': 'fake_spt_uri',
        }

        self.assertEqual(
            expected_node_info,
            common.get_oneview_info(deprecated_node)
        )

        # must be valid
        common.verify_node_info(deprecated_node)

        log_mock.warning.assert_called_once_with(
            "Using 'server_profile_template_uri' in driver_info is "
            "now deprecated and will be ignored in future releases. "
            "Node %s should have it in its properties/capabilities "
            "instead.",
            self.node.uuid
        )

    # TODO(gabriel-bezerra): Remove this after Mitaka
    def test_deprecated_spt_in_driver_info_and_in_capabilites(self):
        # information in capabilities precedes driver_info
        driver_info = db_utils.get_test_oneview_driver_info()
        driver_info['server_profile_template_uri'] = 'unused_fake_spt_uri'

        self.node.driver_info = driver_info

        deprecated_node = self.node
        expected_node_info = {
            'server_hardware_uri': 'fake_sh_uri',
            'server_hardware_type_uri': 'fake_sht_uri',
            'enclosure_group_uri': 'fake_eg_uri',
            'server_profile_template_uri': 'fake_spt_uri',
        }

        self.assertEqual(
            expected_node_info,
            common.get_oneview_info(deprecated_node)
        )

        # must be valid
        common.verify_node_info(deprecated_node)

    def test__verify_node_info(self):
        common._verify_node_info("properties",
                                 {"a": True,
                                  "b": False,
                                  "c": 0,
                                  "d": "something",
                                  "e": "somethingelse"},
                                 ["a", "b", "c", "e"])

    def test__verify_node_info_fails(self):
        self.assertRaises(
            exception.MissingParameterValue,
            common._verify_node_info,
            "properties",
            {"a": 1, "b": 2, "c": 3},
            ["x"]
        )

    def test__verify_node_info_missing_values_empty_string(self):
        with self.assertRaisesRegexp(exception.MissingParameterValue,
                                     "'properties:a', 'properties:b'"):
            common._verify_node_info("properties",
                                     {"a": '', "b": None, "c": "something"},
                                     ["a", "b", "c"])

    def _test_translate_oneview_states(self, power_state_to_translate,
                                       expected_translated_power_state):
        translated_power_state = common.translate_oneview_power_state(
            power_state_to_translate)
        self.assertEqual(translated_power_state,
                         expected_translated_power_state)

    def test_all_scenarios_for_translate_oneview_states(self):
        self._test_translate_oneview_states(
            oneview_states.ONEVIEW_POWERING_OFF, states.POWER_ON)
        self._test_translate_oneview_states(
            oneview_states.ONEVIEW_POWER_OFF, states.POWER_OFF)
        self._test_translate_oneview_states(
            oneview_states.ONEVIEW_POWERING_ON, states.POWER_OFF)
        self._test_translate_oneview_states(
            oneview_states.ONEVIEW_RESETTING, states.REBOOT)
        self._test_translate_oneview_states("anything", states.ERROR)

    @mock.patch.object(common, 'get_oneview_client', spec_set=True,
                       autospec=True)
    def test_validate_oneview_resources_compatibility(self,
                                                      mock_get_ov_client):
        oneview_client = mock_get_ov_client()
        with task_manager.acquire(self.context, self.node.uuid) as task:
            common.validate_oneview_resources_compatibility(task)
            self.assertTrue(
                oneview_client.validate_node_server_hardware.called)
            self.assertTrue(
                oneview_client.validate_node_server_hardware_type.called)
            self.assertTrue(
                oneview_client.check_server_profile_is_applied.called)
            self.assertTrue(
                oneview_client.is_node_port_mac_compatible_with_server_profile.
                called)
            self.assertTrue(
                oneview_client.validate_node_enclosure_group.called)
            self.assertTrue(
                oneview_client.validate_node_server_profile_template.called)
