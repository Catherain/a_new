#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright © 2014-2021 VMware, Inc.  All rights reserved.
# VMware Confidential
"""
Load an OSS/TP manifest file ("osstpmgt.yaml") into the OSS/TP management
system.
"""
import logging
import argparse
from collections import defaultdict
import copy
import getpass
import json
import os
import re
import sys
import textwrap
import traceback
import yaml
from distutils.util import strtobool
from texttable import Texttable

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), os.path.pardir)
)

from settings import setup_client_py_path, MESG_DIR
setup_client_py_path()

import messages
import osstpmgt
import osstploaders
from osstploaders import OSSPackage
from messages import GlobalDefs
from summary import Summary
from client_utils import load_username_apikey, load_password


class Colors(object):
    WARNING = '\033[93m'
    ENDC = '\033[0m'


class Inventory(messages.MessagesBase):
    """
    Class used to represent the inventory defined by the manifest files from
    the command line.  All the manifest files are merged into a single
    inventory for reporting.
    """

    def __init__(
            self,
            server,
            repos_mgrs,
            force_load,
            dryrun,
            requests_config,
    ):
        """
        Constructor.  Takes the server (the OSSTPMGT wrapper class) and the
        user "Force load in absence of sources" flag.
        """
        super(Inventory, self).__init__("otc")
        self.repos_mgrs = repos_mgrs
        self._repository_packages = {}
        self._server = server
        self._force_load = force_load
        self._dryrun = dryrun
        self._requests_config = requests_config
        self.summary = Summary()
        self.package_errors = defaultdict(list) # record the errors occur for the packages, {package1: [error1, error2]} 

    def n_packages(self):
        """
        Return the number of distinct packages loaded.
        """
        result = 0
        for plist in list(self._repository_packages.values()):
            result += len(plist)
        return result

    def add_manifest(self, filename, ignore_none_version=False):
        """
        Add an osstpmgt manifest or provenance file defining packages used
        in a product. If package already exists in the inventory, then the
        data from the manifest for the package is merged into the existing
        package object.

        params:
          ignore_none_version: decide whether or not ignore the package entry with None version
        """
        try:
            with open(filename, "r") as f:
                cur_packages = yaml.load(f)
        except IOError:
            self.error("00021", filename)
            return False
        if isinstance(cur_packages, list):
            cur_packages = self.add_provenance(filename, cur_packages)
            if not cur_packages:
                self.error("00087")
                return False

        if ignore_none_version:
            cur_packages, none_version_packages = self._exclude_none_version_packages(cur_packages)
            # print the warnning information
            self.warning("00083", len(none_version_packages))
            for p in none_version_packages.values():
                print("{}-{}".format(p['name'], p['version']))
            # save the packages with none version into file
            base_name = os.path.splitext(filename)[0]
            none_version_file_path = "{}-none-version-packages.yaml".format(base_name)
            with open(none_version_file_path, 'w') as f:
                f.write(yaml.dump(none_version_packages))
                self.warning("00084", none_version_file_path)

        for name in list(cur_packages.keys()):
            cur_package = cur_packages[name]
            if not self._check_package(cur_package):
                self.error('00034', cur_package)
                return False
            repository = cur_package.get("repository", None)
            if not repository:
                self.error("00022", filename, name)
                return False
            repository = repository.lower()
            if repository == 'gradle':
                # Gradle packages are now managed by the Maven manager.
                repository = 'maven'
                cur_package["repository"] = "Maven"
            self._config_package_request(cur_package)
            if repository not in self._repository_packages:
                self._repository_packages[repository] = {}
            repository_packages = self._repository_packages[repository]
            if name in repository_packages:
                repository_packages[name].merge(cur_package)
            else:
                self._add_package(name, repository_packages, cur_package)
        return True

    def _exclude_none_version_packages(self, cur_packages):
        """
        Split the pacakges into 2 part: pacakges with version, packages with none version
        """
        none_version_packages = {}
        new_cur_packages = {}
        for name in cur_packages.keys():
            pkg = cur_packages[name]
            if pkg['version'] is None:
                none_version_packages[name] = pkg
            else:
                new_cur_packages[name] = pkg
        return new_cur_packages, none_version_packages

    def _config_package_request(self, request):
        """
        Config the package request based on the configurations.
        """
        # Currently we only support the config for interactions
        # the priority of interaction config goes from hightest to lowest:
        # config file > '-I' parameter > manifest file
        default_interactions = self._requests_config.get('default_interactions')
        requests_config = self._requests_config.get('requests', [])
        for request_config in requests_config:
            if request_config['name'] == request['name']:
                if request_config['version'] == 'all' or request_config['version'] == request['version']:
                    request_interactions = request_config.get('interactions')
                    if request_interactions:
                        default_interactions = request_interactions
                break
        if default_interactions:
            request['interactions'] = default_interactions

    def add_provenance(self, filename, file_content):
        """
        Add a provenance file defining packages used in a product.
        :param filename:
        :param file_content: packages info from 'server.yaml'
        :return:
        """

        # The default repository for provenance file packages is "VMWsource"
        default_repository = 'VMWsource'
        # The result packages
        packages = {}
        # The packages info in packages.yaml file
        pro_packages = None

        for package in file_content:
            if isinstance(package, dict):
                # convert (with attribute adjustments) to a dictionary
                for app_name, package_info_list in list(package.items()):
                    for package_info in package_info_list:
                        self._convert_package(packages,
                                              default_repository,
                                              package_info)
            elif isinstance(package, str):
                # the data should be pulled from "packages.yaml"
                if not pro_packages:
                    # the path for packages.yaml
                    packages_file = 'packages.yaml'
                    if os.path.dirname(filename):
                        packages_file = '{0}{1}{2}'.format(
                            os.path.dirname(filename),
                            os.path.sep,
                            packages_file)
                    try:
                        with open(packages_file, "r") as f:
                            pro_packages = yaml.load(f)
                    except IOError:
                        self.error("00032", packages_file, filename)

                is_found = False
                for pro_package in pro_packages:
                    if package in pro_package:
                        for pro_package_info in pro_package[package]:
                            self._convert_package(packages,
                                                  default_repository,
                                                  pro_package_info)
                        is_found = True
                        break
                if not is_found:
                    self.error("00033", package)
                    return False
        return packages

    def _check_package(self, package):
        """
        The package must has name and version info
        :param package:
        :return:
        """
        return package.get('name') and package.get('version')

    def _convert_package(self, packages, repository, pro_package):
        """
        Convert a package in provenance file to dict
        :param repository:
        :param pro_package:
        :return:
        """
        repository = pro_package.get('repository', repository)
        # repository from blackduck scanning
        bd_repository = pro_package.get('bd_metadata', {}).get('external_namespace')
        if self._is_baseos_from_blackduck_scan(bd_repository):
            # treat it as BaseOS package
            repository = 'BaseOS'

        name = pro_package['name']
        version = pro_package['version']
        group = artifact = None
        if repository.lower() in ['maven', 'gradle']:
            try:
                group, artifact = name.split(":", 1)
            except ValueError:
                self.fatal("00059", name)
        gobuild_interactions = pro_package.get('uses', None) or pro_package.get('interactions', None)
        osm_interactions = self._convert_gobuild_interactions(
            gobuild_interactions
        )
        new_key = '{0}:{1}:{2}'.format(repository.lower(), name, version)
        new_value = {
            'name': name,
            'version': version,
            'repository': repository,
            'license': pro_package.get('licenses', 'UNKNOWN'),
            'modified': pro_package.get('modified', 'No'),
            'url': pro_package.get('url', None),
            'other-distribution': pro_package.get('other-distribution', None),
            'interactions': osm_interactions,
            'bd_component_id': pro_package.get('bd_metadata', {}).get('component_id'),
            'bd_version_id': pro_package.get('bd_metadata', {}).get('version_id'),
            'bd_origin_id': pro_package.get('bd_metadata', {}).get('origin_id'),
        }
        if bd_repository and repository == 'BaseOS':
            # if it's a blackduck identified package and its repository is BaseOS, set the `baseos-osname`.
            # bd_repository always is `ubuntu`, `centos` ...
            new_value['baseos-osname'] = bd_repository
        if group and artifact:
            new_value['maven-groupId'] = group
            new_value['maven-artifactId'] = artifact
            new_value['maven-scopes'] = ['compile']
        if pro_package.get("golang-source"):
            new_value["golang-source"] = pro_package.get("golang-source")
        packages[new_key] = new_value

    BASE_OS_BD_REPO = [
        'ubuntu', 'centos', 'photon', 'alpine', 'debian', 'redhat',
        'opensuse', 'fedora'
    ]

    def _is_baseos_from_blackduck_scan(self, bd_repo):
        """
        If the repository from blackduck is a BaseOS repository
        """
        return bd_repo in self.BASE_OS_BD_REPO

    def _convert_gobuild_interactions(self, gobuild_interactions):
        """
        Convert interaction type value from Gobuild to the OSM value
        """
        if not gobuild_interactions:
            return []
        if isinstance(gobuild_interactions, str):
            gobuild_interactions = [gobuild_interactions]
        osm_interactions = []
        for interaction in gobuild_interactions:
            osm_interaction = self._server.convert_gobuild_interaction(
                interaction)
            if osm_interaction:
                osm_interactions.append(osm_interaction)
            else:
                self.fatal("00077", interaction)
        return osm_interactions

    def _add_package(self, name, packages, new_data):
        """
        Add a new package to the inventory.  Validation is called after the
        object is created.  This where unsupported repository will throw an
        error.
        """
        new_package = self.repos_mgrs.get_package(name, new_data)
        if new_package is not None:
            packages[name] = new_package

    def bd_package_mapping(self, product, version):
        if not product or not version:
            return

        packages = []
        for repo_packages in list(self._repository_packages.values()):
            packages.extend(list(repo_packages.values()))

        bd_packages = []
        for package in packages:
            if not package._data.get("bd_component_id") or not package._data.get("bd_version_id"):
                continue
            bd_packages.append(
                {
                    'fullname': package.fullname(),
                    'name': package.name(),
                    'version': package.version(),
                    'repository': package.repository(),
                    'bd_component_id': package._data['bd_component_id'],
                    'bd_version_id': package._data['bd_version_id'],
                }
            )

        if not bd_packages:
            return

        self.info("10157")

        requests = self._server.get_requests(product, version)

        osm_packages = []
        for request in requests['results']:
            master_ticket_id = request['master_package'].split('/')[-2]
            name = request['master_package_name']
            version = request['master_package_version']
            bd_component_id = request['master_package_component_id']
            bd_version_id = request['master_package_version_id']
            osm_packages.append(
                {
                    'master_ticket_id': master_ticket_id,
                    'name': name,
                    'version': version,
                    'bd_component_id': bd_component_id,
                    'bd_version_id': bd_version_id,
                    'request_id': request['id'],
                    'resolution': request['resolution'],
                    'interaction_type': request['interaction_type']
                }
            )

        for bd_package in bd_packages:
            for osm_package in osm_packages:
                # Match with black duck ids
                if bd_package['bd_component_id'] == osm_package['bd_component_id'] and \
                   bd_package['bd_version_id'] == osm_package['bd_version_id']:
                   # set package_id
                    _pkg = self._repository_packages[
                        bd_package['repository'].lower()
                    ][bd_package['fullname']]
                    _pkg._package_id = osm_package['master_ticket_id']
                    # set request_id
                    _pkg._request_id = osm_package['request_id']
                    _pkg._request_status = osm_package['resolution']
                    _pkg.set_original_interactions(osm_package, self._server)
                    self.info("10158", bd_package['fullname'])
                    continue

                # Match with name and version
                osm_name, osm_version = self.convert_name_and_version(
                    osm_package['name'], osm_package['version']
                )
                bd_name, bd_version = self.convert_name_and_version(
                    bd_package['name'], bd_package['version']
                )
                if osm_name == bd_name and osm_version == bd_version:
                    self._repository_packages[
                        bd_package['repository'].lower()
                    ][bd_package['fullname']]._package_id = osm_package['master_ticket_id']
                    self._repository_packages[
                        bd_package['repository'].lower()
                    ][bd_package['fullname']]._request_id = osm_package['request_id']
                    self.info("10159", bd_package['fullname'])

    @staticmethod
    def convert_name_and_version(name, version):
        """
        Convert blackduck packages and osm-packages into the same format
        """
        name = name.lower()
        version = version.lower()

        name = name.replace(' ', '-')
        name = re.sub('[-.]js$', '', name)
        name = re.sub('---.*$', '', name)
        name = re.sub('[-_.:/@]', '', name)

        version = re.sub('[< >]', '', version)
        version = re.sub('^[vV]', '', version)

        return name, version

    def query_packages(self):
        """
        Query the OSS/TP system for pre-existing package tickets in the
        loaded inventory.
        """
        for repository in list(self._repository_packages.keys()):
            self.info("10042", repository)
            for package in list(self._repository_packages[repository].values()):
                try:
                    if package.locate_package(self._server):
                        self._ack_package(package)
                except Exception as e:
                    self._add_package_error(package, e)
                    continue

    def _ack_package(self, package):
        """
        Acknowledge a pre-existing package.
        """
        self.info("10043", str(package))
        self._upload_source(package)

    def _upload_source(self, package):
        """
        If the package in the system does not already have
        sources associated with it and we have access
        to a source stream, then also upload sources.
        """

        if package.source_uploaded(self._server) or self._dryrun:
            return
        src_stream = package.get_src_stream()
        if src_stream is None:
            return
        # Sources haven't already been uploaded and we have a handle
        # on a source bundle, upload it.
        self.info("10044", str(package))
        package.upload_source(self._server, src_stream)

    def query_requests(self, product, version):
        """
        Query the OSS/TP system for pre-existing request tickets against
        the given release in the loaded inventory.
        """
        self.info("10045", product, version)
        for repository in list(self._repository_packages.keys()):
            self.info("10046", repository)
            for package in list(self._repository_packages[repository].values()):
                try:
                    self.query_request(package, product, version)
                except Exception as e:
                    self._add_package_error(package, e)
                    continue

    def query_request(self, package, product, version):
        """
        Query the OSS/TP system for a pre-existing request ticket for an
        individual package against the given release in the loaded inventory.
        """
        if package.locate_request(self._server, product, version):
            for feature in package.add_features(self._server):
                self.info("10054", feature, package.request_id())
                request_remained = self.summary.package.found.remained
                request_merged_feature = self.summary.package.found.merged_feature
                request_merged_feature.add_package(
                    package.request_id(),
                    package.name(),
                    package.version()
                )

            status = package.request_status()
            # status is the `resolution` in OSM
            status = "OPEN" if status == "" else status
            self.info("10047", package.request_id(), str(package), status)
            return True
        else:
            return False

    def update_requests_in_group(self, request_group):
        """
        Update the requests for packages in the inventory in the target group.
        Return a list of request ids which are removed from the target group.
        """
        if self._dryrun:
            self.info('10172')
            return []
        origin_request_ids = set(request_group['use_tickets'])
        current_request_ids = set()
        for repository in self._repository_packages.keys():
            for package in self._repository_packages[repository].values():
                if not package.request_id():
                    # the BaseOS packages don't have a request_Id
                    self.info('10189', package.name(), package.version())
                    continue
                current_request_ids.add(package.request_id())
        if origin_request_ids == current_request_ids:
            self.info('10181', request_group['group_name'], request_group['group_version'])
            return []
        data = {'use_tickets': list(current_request_ids)}
        self._server.patch_group(request_group['id'], data)
        new_requests_in_group = current_request_ids - origin_request_ids
        self.info('10173', len(new_requests_in_group),
            request_group['group_name'], request_group['group_version'])
        outdated_requests_in_group = origin_request_ids - current_request_ids
        self.info('10182', len(outdated_requests_in_group),
            request_group['group_name'], request_group['group_version'])
        return list(outdated_requests_in_group)

    def create_requests(self, product, version):
        """
        Create requests for packages in the inventory that don't already
        have tickets.
        """
        n_found = 0
        request_created = self.summary.package.created
        request_skipped = self.summary.package.skipped
        request_remained = self.summary.package.found.remained
        request_reopened = self.summary.package.found.reopened
        request_merged_interaction = self.summary.package.found.merged_interaction
        request_merged_feature = self.summary.package.found.merged_feature
        for repository in list(self._repository_packages.keys()):
            self.info("10048", repository)
            for package in list(self._repository_packages[repository].values()):
                if package.request_id() is None:
                    if package.can_create_request():
                        if self._dryrun:
                            self.info("10139",
                                      str(package),
                                      product,
                                      version)
                        else:
                            try:
                                if self.repos_mgrs.create_request(
                                    self._server,
                                    package,
                                    product,
                                    version
                                ):
                                    request_created.add_package(
                                        package.request_id(),
                                        package.name(),
                                        package.version()
                                    )
                            except Exception as e:
                                if "Found duplicate" in "".join(e.args):
                                    n_found += 1
                                    self._resolve_request_duplicated_error(package,product,version)
                                else:
                                    self.error("00065", package.fullname(), str(e))
                                    self._add_package_error(package, e)
                                continue
                    else:
                        request_skipped.add_package(
                            package.request_id(),
                            package.name(),
                            package.version()
                        )
                else:
                    n_found += 1
                    request_remained.add_package(
                        package.request_id(),
                        package.name(),
                        package.version()
                    )
                    # reopen non-issue'ed packages
                    if package.request_status() == 'NON-ISSUE':
                        if self._dryrun:
                            self.info("10083",
                                      package.request_id(),
                                      package.fullname(),
                                      product,
                                      version)
                        else:
                            try:
                                package.reopen_request(self._server,
                                                    product,
                                                    version)
                            except Exception as e:
                                self._add_package_error(package, e)
                                continue
                        request_reopened.add_package(
                            package.request_id(),
                            package.name(),
                            package.version(),
                        )
                        request_remained.pop_package(package.request_id())

                    increased = package.additional_interactions()
                    if increased:
                        if self._dryrun:
                            self.info("10130",
                                      increased,
                                      package.request_id())
                        else:
                            try:
                                package.merge_interactions(self._server,
                                                        increased)
                            except Exception as e:
                                self._add_package_error(package, e)
                                continue
                            else:
                                request_merged_interaction.add_package(
                                    package.request_id(),
                                    package.name(),
                                    package.version()
                                )
                        request_remained.pop_package(package.request_id())

                # Set INTERNAL-ONLY packages.
                if (package.is_internal_only() and
                        package.request_status() != 'INTERNAL-ONLY'):
                    if not self._dryrun:
                        self.info("10091", str(package))
                        try:
                            package.set_request_internal(
                                self._server,
                                product,
                                version
                            )
                        except Exception as e:
                            self._add_package_error(package, e)
                            continue
                    else:
                        self.info("10092", str(package))
        # pop merged_feature package
        for package in request_merged_feature.results:
            request_remained.pop_package(package['id'])
        if self._dryrun:
            return
        self.info("10049", n_found, request_reopened.count, request_created.count, request_merged_interaction.count)
        if request_skipped.count > 0:
            self.info("10050", request_skipped.count)

    def create_packages(self):
        """
        Create package tickets for packages in the inventory that don't already
        have tickets.
        """
        master_package_found = self.summary.master_package.found
        master_package_created = self.summary.master_package.created
        master_package_skipped = self.summary.master_package.skipped
        for repository in list(self._repository_packages.keys()):
            for package in list(self._repository_packages[repository].values()):
                if package.package_id() is None:
                    if package.can_create():
                        if self._dryrun:
                            self.info("10138", str(package))
                        else:
                            try:
                                package_info = package.create_package(
                                    self._server,
                                    package.get_src_stream(),
                                    self._force_load
                                )
                            except Exception as ex:
                                if "Found duplicate master package" in " ".join(ex.args):
                                    self._resolve_master_package_duplicated_error(package)
                                else:
                                    self.error("00065", package.fullname(), str(ex))
                                    self._add_package_error(package, ex)
                                continue
                            master_package_created.add_package(
                                package_info['id'],
                                package_info['name'],
                                package_info['version']
                            )
                    else:
                        master_package_skipped.add_package(
                            package.package_id(),
                            package.name(),
                            package.version(),
                        )
                else:
                    master_package_found.add_package(
                        package.package_id(),
                        package.name(),
                        package.version()
                    )

        if self._dryrun:
            return
        self.info("10052", master_package_found.count, master_package_created.count)
        if master_package_skipped.count > 0:
            self.info("10053", master_package_skipped.count)

    def reupload_source(self):
        """
        It is possible that 504 timeout or other server
        error is encountered. Retry one more time to upload
        the source bundle for packages whose
        `upload_source_failure` is marked as True
        """
        failed_packages = self._get_upload_failed_packages()

        if failed_packages:
            self.info("00067", len(failed_packages))
            for package in failed_packages:
                try:
                    self._upload_source(package)
                except Exception as e:
                    self._add_package_error(package, e)
                    continue

        failed_packages = self._get_upload_failed_packages()
        if failed_packages:
            self.warning(
                "00068",
                len(failed_packages),
                ', '.join(
                    ['#' + str(p.package_id())
                     for p in failed_packages]
                )
            )

    def _get_upload_failed_packages(self):
        """ Get packages whose `upload_source_failure` is marked as True"""

        failed_packages = []
        for repo in list(self._repository_packages.keys()):
            for package in list(self._repository_packages[repo].values()):
                if package.upload_source_failure:
                    failed_packages.append(package)
        return failed_packages

    def _add_package_error(self, package: "OSSPackage", error: "Exception"):
        self.package_errors[package].append(error)

    def summarize_requests(self):
        """
        Summarize any issues with the tickets for the release, i.e., includes
        references to denied, internal-only or non-issue'ed tickets.
        """
        if self._dryrun:
            return
        denied = []
        internal_only = []
        non_issue = []
        reopened = []
        for repository in list(self._repository_packages.keys()):
            for package in list(self._repository_packages[repository].values()):
                if package.request_status() == 'DENIED':
                    denied.append(package)
                elif package.request_status() == 'INTERNAL-ONLY':
                    internal_only.append(package)
                elif package.request_status() == 'NON-ISSUE':
                    non_issue.append(package)
                elif package.request_status() == 'REOPENED':
                    reopened.append(package)
        self._display_extra_list(reopened, "REOPENED")
        self._display_extra_list(denied, "DENIED")
        self._display_extra_list(internal_only, "INTERNAL-ONLY")
        self._display_extra_list(non_issue, "NON-ISSUE")

    def _display_extra_list(self, packages, status):
        """
        Utility method to display a list of tickets with issues that should
        be addressed by the end user.
        """
        if len(packages) > 0:
            self.warning("00024", status)
            for package in packages:
                self.warning("00025", package.request_id(), str(package))

    def exclude_packages(self):
        """
        Exclude packages from the inventory based on predefined rules,
        i.e., sub_class of 'PackageExcluderBase'
        """
        report = {}
        helper = osstploaders.PackageExcluderHelper()
        customized_excludes = self._collect_customized_excluded_packages()
        helper.add_excluder(
            osstploaders.CustomizedNameVersionExcluder(name_versions=customized_excludes)
        )

        copied_dict = copy.deepcopy(self._repository_packages)
        for repo in list(copied_dict.keys()):
            for full_name, pkg in list(copied_dict[repo].items()):
                matched_excluder = helper.match(pkg)
                if matched_excluder:
                    self.summary.master_package.excluded.add_package(
                        pkg.package_id(),
                        pkg.name(),
                        pkg.version()
                    )
                    orig_pkg = self._repository_packages[repo].pop(full_name)
                    self.repos_mgrs.delete(orig_pkg)
                    report[full_name] = matched_excluder
        if report:
            # report excluded packages order by 'full_name'
            for full_name in sorted(report.keys()):
                matched_excluder = report[full_name]
                self.info("10140", full_name, matched_excluder.name())
            self.info("10141", len(report))
            self.info("10142", helper.description())

    def _collect_customized_excluded_packages(self):
        """
        Collect the pacakges with `excluded` field true
        in the configuration file specified by option `-C`

        return a list of name, version pairs:
            [(name1, version1), (name2, version2)]
        """
        excluded_requests = []
        if self._requests_config:
            if 'requests' in self._requests_config:
                for request in self._requests_config['requests']:
                    if request.get('excluded', False) == True:
                        excluded_requests.append(
                            (
                                request['name'],
                                request['version'],
                            )
                        )
        return excluded_requests

    def _resolve_master_package_duplicated_error(self,package):
        """
        This error occurs because this package was created earlier in another parallel thread,
        so we need to classify it as the packge of master_package_found
        """
        package.locate_package(self._server)
        self._ack_package(package)
        master_package_found = self.summary.master_package.found
        master_package_found.add_package(
            package.package_id(),
            package.name(),
            package.version()
        )
    
    def _resolve_request_duplicated_error(self,package,product,version):
        """
        This error occurs because this package was created earlier in another parallel thread,
        so we need to classify it as found
        """
        package.locate_request(self._server, product, version)
        for feature in package.add_features(self._server):
            self.info("10054", feature, package.request_id())
            request_merged_feature = self.summary.package.found.merged_feature
            request_merged_feature.add_package(
                package.request_id(),
                package.name(),
                package.version()
            )
        status = package.request_status()
        # status is the `resolution` in OSM
        status = "OPEN" if status == "" else status
        self.info("10047", package.request_id(), str(package), status)


class OSSTPLoad(messages.MessagesBase):

    def __init__(self):
        super(OSSTPLoad, self).__init__("otc")
        self.no_proxy()
        self.parser = argparse.ArgumentParser(description=__doc__)
        self.parser.add_argument(
            "-H",
            dest="error_code",
            metavar="ERROR-CODE",
            help=self.format("10016")
        )
        self.parser.add_argument(
            "-n",
            dest="dryrun",
            action='store_true',
            default=False,
            help=self.format("10034")
        )
        self.parser.add_argument(
            "-F",
            dest="force_load",
            action='store_true',
            default=False,
            help=self.format("10035")
        )
        self.parser.add_argument(
            "-R",
            dest="release",
            help=self.format("10036")
        )
        self.parser.add_argument(
            "-a",
            metavar="REPOSITORY",
            dest="complete",
            action='append',
            default=[],
            type=str,
            help=self.format("10084")
        )
        self.parser.add_argument(
            "-U",
            dest="username",
            metavar="USERNAME",
            default=os.environ.get("USER", os.environ.get("USERNAME", None)),
            type=str,
            help=self.format("10037")
        )
        self.parser.add_argument(
            "-P",
            dest="pwfile",
            metavar="PASSWD-FILE",
            type=str,
            help=self.format("10038")
        )
        self.parser.add_argument(
            "-A",
            dest="apikey_file",
            type=str,
            help="File containing username and apikey"
        )
        self.parser.add_argument(
            "-S",
            dest="server_name",
            metavar="SERVER-NAME",
            default="default",
            type=str,
            help=self.format("10040")
        )
        self.parser.add_argument(
            "osstpfiles",
            metavar='OSSTPFILE',
            type=str,
            nargs='*',
            help=self.format("10041")
        )
        group = self.parser.add_argument_group(
            "Internal Options",
            "Options that should only be used if requested by the OSS/TP group"
        )
        self.parser.add_argument(
            "--noinput",
            dest="noinput",
            action='store_true',
            default=False,
            help=self.format("10076")
        )
        self.parser.add_argument(
            "-I",
            dest="interactions",
            help=self.format("10154")
        )
        arg_group = self.parser.add_argument_group('Use Ticket Group')
        arg_group.add_argument(
            "-gn",
            "--group-name",
            dest="group_name",
            required=False,
            help=self.format("10164")
        )
        arg_group.add_argument(
            "-gv",
            "--group-version",
            dest="group_version",
            required=False,
            help=self.format("10165")
        )
        arg_group.add_argument(
            "-gl",
            "--group-label",
            dest="group_label",
            required=False,
            help=self.format("10186")
        )
        arg_group.add_argument(
            "--multiple-group-versions",
            dest="multiple_group_versions",
            action='store_true',
            default=False,
            help=self.format("10166")
        )
        self.parser.add_argument(
            "-C",
            dest="config_file",
            help=self.format("10155")
        )
        self.parser.add_argument(
            "--ignore-none-version",
            dest="ignore_none_version",
            default=False,
            action='store_true',
            help=self.format("10188")
        )
        self.parser.add_argument(
            "--debug",
            dest="debug",
            action='store_true',
            default=False,
            help=self.format("10156")
        )
        # args.summary will be:
        # bool when without --summary
        # NoneType when with --summary
        # str when with --summary <file_path/filename>
        self.parser.add_argument(
            "--summary",
            dest="summary",
            nargs='?',
            default=False,
            help=self.format("10185")
        )
        self.repos_mgrs = osstploaders.RepositoryManagers()
        self.repos_mgrs.add_command_line_args(self.parser)
        self.server = None
        self.requests_config = {}
        self.release = None
        self.request_group_name = None
        self.request_group_version = None
        self.request_group_label = None
        self.request_group = None
        self.multiple_group_versions = None
        self.dryrun = None
        self.summary = None

    def _load_interactions(self, interactions):
        if not interactions:
            self.debug("00075")
            return True
        interactions = interactions.split(',')
        interactions = [i.strip() for i in interactions if i.strip()]
        for interaction in interactions:
            if not self.server.check_interaction(interaction):
                self.error("00076", interaction)
                return False
        self.requests_config['default_interactions'] = interactions
        return True

    def _check_use_ticket_group_options(self, args):
        """
        Check the options related to the use ticket group
        """
        if bool(args.group_name) ^ bool(args.group_version):
            self.error('00082')
            return False

        if args.group_name and not args.release:
            self.error('00086')
            return False

        if args.group_name and args.baseos_ct_tracker:
            self.error('00085')
            return False


        if args.group_name:
            self.request_group_name = args.group_name
            self.info('10167', self.request_group_name)
            self.request_group_version = args.group_version
            self.info('10168', self.request_group_version)
            self.request_group_label = args.group_label
            self.multiple_group_versions = args.multiple_group_versions
        return True

    def _load_config_file(self, config_file):
        """
        Load and validate the config file
        """
        if not config_file:
            self.debug("00073")
            return True
        try:
            with open(config_file, 'r') as c_file:
                config = yaml.load(c_file)
        except IOError as e:
            self.error("00074", config_file, str(e))
            return False
        # Schema validation starts
        REQUESTS = 'requests'
        requests_config = config.get(REQUESTS)
        if not requests_config:
            self.error("00079", REQUESTS)
            return False
        required_fields = ['name', 'version']
        for request_config in requests_config:
            for field in required_fields:
                if field not in request_config:
                    self.error("00079", field)
                    return False
            interactions = request_config.get('interactions')
            if not interactions:
                continue
            for interaction in interactions:
                if not self.server.check_interaction(interaction):
                    self.error("00076", interaction)
                    return False
        # Schema validation ends
        self.requests_config.update(config)
        return True

    def _get_or_create_request_group(self):
        """
        Try to find the request group in the current release and create a new one
        if it doesn't exist yet.
        Delete the groups with the same name but different versions if the
        'multiple_group_versions' is set to False
        """
        params = {
            'release': self.release['id'],
            'group_name': self.request_group_name
        }
        groups_with_same_name = self.server.find_request_groups(params)
        for index, request_group in enumerate(groups_with_same_name[:]):
            if request_group['group_version'] == self.request_group_version:
                # Found an existing group with the same name and version
                self.request_group = request_group
                groups_with_same_name.pop(index)
        if not self.request_group:
            # No existing group has the same name and version, so create a new one
            params['group_version'] = self.request_group_version,
            if self.request_group_label != None:
                params['group_label'] = self.request_group_label
            if not self.dryrun:
                self.request_group = self.server.create_request_group(params)
                self.info('10174', self.request_group_name, self.request_group_version)
            else:
                self.info('10175', self.request_group_name, self.request_group_version)
        else:
            # Found a existing group which has the same name and version
            self.info('10176', self.request_group_name, self.request_group_version)
            # Update the label if necessary
            if self.request_group_label != None and \
                    self.request_group_label != request_group['group_label']:
                if not self.dryrun:
                    data = {'group_label': self.request_group_label}
                    self.server.patch_group(request_group['id'], data)
                self.info('10187', request_group['group_label'], self.request_group_label)
        # Remove groups with same name but different versions if necessary
        if groups_with_same_name and not self.multiple_group_versions:
            for request_group in groups_with_same_name:
                if not self.dryrun:
                    self.server.delete_request_group(request_group['id'])
                    self.info('10177', request_group['group_name'], request_group['group_version'])
                else:
                    self.info('10178', request_group['group_name'], request_group['group_version'])

    def execute(self):
        """
        Main routine: Handle command line arguments and perform the scan.
        """
        inventory = None
        try:
            args = self.parser.parse_args()
            if args.error_code:
                self.help_on_error(args.error_code)
                return

            if args.debug:
                # enable debug level log to see the
                # url of the requests that have been sent out
                logging.basicConfig(level=logging.DEBUG)

            self.repos_mgrs.handle_command_line_args(args)

            if len(args.osstpfiles) == 0:
                self.error("00027")
                return 1

            if args.server_name == 'default':
                # default using production
                # show confirmation prompt if no specified server
                args.server_name = 'production'
                if not args.noinput and not args.dryrun and not self.prompt(
                        self.format("10077")):
                    return 1

            if args.apikey_file:
                apikey = load_username_apikey(args.apikey_file)
                if not apikey:
                    print("Invalid ApiKey file! ApiKey file should contain one line with: \n" \
                          "username@vmware.com <your api key>")
                    return 1
                self.server = osstpmgt.OSSTPMGT(
                    apikey=apikey,
                    servername=args.server_name,
                )
            else:
                username = args.username
                if not username:
                    username = input(self.format("10032"))
                if args.pwfile:
                    password = load_password(args.pwfile)
                else:
                    password = getpass.getpass(
                        self.format("10033", username, args.server_name)
                    )
                self.server = osstpmgt.OSSTPMGT(
                    username=username,
                    password=password,
                    servername=args.server_name,
                )

            # Get warning message from server if any
            for msg in self.server.client_messages:
                print('\n{}\n'.format(Colors.WARNING + msg['message'] + Colors.ENDC))

            if args.server_name == 'production':
                self.warning("10078")
            else:
                self.warning("00031", args.server_name)

            self.dryrun = args.dryrun
            dryrun_mode = 'on' if self.dryrun else 'off'
            self.info('10171', dryrun_mode)

            if not self._load_config_file(args.config_file):
                return 1

            if isinstance(args.summary, bool):  # without --summary
                self.summary = False
            elif args.summary is None:  # with --summary
                self.summary = 'summary.json'
            elif isinstance(args.summary, str):  # with --summary <file_path/filename>
                self.summary = args.summary

            if args.force_load:
                self.warning('10137')

            inventory = Inventory(
                self.server,
                self.repos_mgrs,
                args.force_load,
                args.dryrun,
                self.requests_config
            )
            product = None
            version = None
            if not self._check_use_ticket_group_options(args):
                return 1

            if args.release:
                if '/' not in args.release:
                    self.error("00026")
                    return 1
                product, version = args.release.split('/', 1)
                self.release = self.server.verify_release(product, version)
                inventory.summary.release.name = product
                inventory.summary.release.version = version
                if not self._load_interactions(args.interactions):
                    return 1
                if self.request_group_name and self.request_group_version:
                    self._get_or_create_request_group()
            for filename in args.osstpfiles:
                if not inventory.add_manifest(
                    filename,
                    ignore_none_version=args.ignore_none_version
                ):
                    return 1
            if inventory.n_packages() == 0:
                self.error("00028")
                return 1
            inventory.exclude_packages()
            inventory.bd_package_mapping(product, version)
            inventory.query_packages()
            inventory.create_packages()
            inventory.reupload_source()
            kwargs = {'acknowledge_by_group': False}
            if product and version:
                inventory.query_requests(product, version)
                inventory.create_requests(product, version)
                inventory.summarize_requests()
                if self.request_group:
                    kwargs = {'acknowledge_by_group': True}
                    kwargs['outdated_requests_in_group'] = inventory.update_requests_in_group(
                        self.request_group)
                    kwargs['release_id'] = self.release['id']
            self.repos_mgrs.acknowledge_osstpload(
                self.server,
                product,
                version,
                args.dryrun,
                inventory.summary,
                kwargs
            )
            if inventory.package_errors:
                self.report_error_packages(inventory)
                raise osstpmgt.OSSTPMGTError("X009")

        except osstpmgt.OSSTPMGTError as ex:
            self.error("00030", str(ex.code), str(ex))
            return 1
        except Exception as ex:
            if args.debug:
                traceback.print_exc(file=sys.stdout)
            else:
                raise ex
        finally:
            if self.summary and inventory:
                inventory.summary.warnings = GlobalDefs.warnings
                inventory.summary.errors = GlobalDefs.errors

                dirname = os.path.dirname(self.summary)
                if dirname and not os.path.exists(dirname):
                    os.makedirs(dirname)
                with open(self.summary, 'w') as summary_file:
                    json.dump(inventory.summary.to_dict(), summary_file, indent=2)
        return 0

    def help_on_error(self, error_code):
        """
        Print help information for an error code.
        """
        if '-' in error_code:
            facility, message_id = error_code.split('-', 1)
        else:
            facility, message_id = "otc", error_code
        mesg_text = messages.message_text(facility, message_id)
        if mesg_text is None:
            self.error('00005', error_code)
            return
        self.info('10013', error_code, mesg_text)
        help_info = messages.message_comments(facility, message_id)
        if help_info:
            self.info('10014')
            for line in textwrap.wrap(help_info):
                self.info('10015', line.strip())
        else:
            self.error('00006', error_code)

    def no_proxy(self):
        """
        Remove any proxy settings in the environment: this script makes direct
        connections to the OSS/TP system.
        """
        for var in list(os.environ.keys()):
            if 'proxy' in var.lower():
                del os.environ[var]

    def report_error_packages(self, inventory: "Inventory"):
        """
        Print the Inventory.package_errors in a pretty way
        """
        table = Texttable(max_width=160)
        rows = [["Package", "Error(s)"]]
        for package, errors in inventory.package_errors.items():
            row = [str(package), '\n\n'.join([str(e) for e in errors])]
            rows.append(row)
        table.add_rows(rows)
        print(table.draw())

    def prompt(self, query):
        sys.stdout.write('%s [y/n]: ' % query)
        val = input()
        try:
            ret = strtobool(val)
        except ValueError:
            sys.stdout.write('Please answer with a y/n\n')
            return self.prompt(query)
        return ret


if __name__ == "__main__":
    try:
        messages.include_codes(True)
        messages.add_mesg_directory(MESG_DIR)
        sys.exit(OSSTPLoad().execute())
    except Exception as ex:
        sys.stderr.write("{0}\n".format(
            str(ex)
        ))
        sys.exit(1)
