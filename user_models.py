# -*- encoding: utf-8 -*-
# Copyright 2013, 2014 VMware, Inc.  All rights reserved.
# VMware Confidential
"""
Django models corresponding the SCOTzilla (Bugzilla) based schema.
"""
from __future__ import print_function

from builtins import str  # pylint:disable=redefined-builtin
import datetime
import pytz

from django.db import models, connection
from django.db.models import Q
from django.conf import settings
from django.contrib.auth.models import User

from github_manager.models import RepoRequestStatus, RepoGitHubStatus, GitHubRepoDashboard, GitHubRepo
from scotzilla import models as scot_models
from scotzilla.models import (
    CTConfirmStatusEnum,
    LicenseReviewTicketAttachments,
    OssProjectType,
    UCTicketStateEnum,
    UCTicketResolutionEnum,
    OssProjectTicket
)

from scanning.models import HubLicense, License
from release.models import RMRelease_Mapping, Release

from .utils import TimezoneUtils

utils = TimezoneUtils()


def get_users_below_user(self):
    """
    This will get all of the user id's below a user
    according to the ldap data stored in the UserProfile
    Model
    """
    cursor = connection.cursor()
    query = """
            with recursive orgtree (id, depth, path, cycle) as (
            select %s as id, 1, ARRAY[%s], false

            union all

            select u.id as id, ot.depth+1, path || u.id, u.id=ANY(path)
            from auth_user u
                join user_userprofile up on (up.user_id = u.id)
                join orgtree ot on (ot.id = up.manager_id)
                WHERE NOT cycle

        )
        select DISTINCT u.id
        from   orgtree ot
        ,      auth_user u
        where  ot.id = u.id
        and    u.is_active;
            """
    cursor.execute(query, [self.id, self.id])
    results = cursor.fetchall()
    user_list = []

    for r in results:
        user_list.append(r[0])

    return user_list


def get_uncompleted_tasks(self):

    user_tasks = {}

    # Prefilter common filters
    package_use = scot_models.UseTicket.objects.filter(
        status__in=scot_models.UTStateEnum.ACTIVE_STATUS,
    )

    taks1 = get_prod_mgr_pending_comp_terms_task(self, package_use)
    if taks1:
        user_tasks['prod_mgr_pending_comp_terms'] = taks1

    taks2 = get_developer_pending_comp_terms_task(self, package_use)
    if taks2:
        user_tasks['developer_pending_comp_terms'] = taks2

    taks3 = get_releases_ga_unlocked_list_task(self)
    if taks3:
        user_tasks['releases_ga_unlocked'] = taks3

    taks4 = get_unmapped_blackduck_licenses_task(self)
    if taks4:
        user_tasks['unmapped_blackduck_licenses'] = taks4

    taks5 = get_need_fill_lic_expiration_date_pkgs_task(self, package_use)
    if taks5:
        user_tasks['tp_packages_need_lic_expiration_date'] = taks5

    task6 = get_tp_pkgs_is_going_to_be_expired(self, package_use)
    if task6:
        user_tasks['tp_packages_is_going_to_be_expired'] = task6

    task7 = get_dev_newer_version_pkgs_task(self, package_use)
    if task7:
        user_tasks['dev_newer_version_pkgs'] = task7

    task8 = get_pm_newer_version_releases(self, package_use)
    if task8:
        user_tasks['pm_newer_version_pkgs'] = task8

    task9 = get_releases_without_mapping(self)
    if task9:
        user_tasks['unmapped_releases'] = task9

    task10 = get_java_oracle_usage(self, package_use)
    if task10:
        user_tasks['java_oracle_usage'] = task10

    return user_tasks or None


def get_prod_mgr_pending_comp_terms_task(user, pkgs):
    prod_mgr_pending_comp_terms = pkgs.filter(
        release__owners__product_mgr=user,
        pm_compterms_validation=CTConfirmStatusEnum.PENDING,
        status__in=['CONFIRM CT'],
        release__is_locked=False,
    )
    prod_mgr_pending_comp_terms = prod_mgr_pending_comp_terms.count()

    if prod_mgr_pending_comp_terms:
        url = (
            "#/compliance-terms?order_by=master_ticket__name&"
            "status__in=CONFIRM CT&"
            "pm_compterms_validation__in=PENDING ACCEPTANCE&"
            "_adv_release__owners__product_mgr__username={}&"
            "_persona=product-manager"
        ).format(user.username)
        return {
            'name': 'Unconfirmed Product Manager Compliance Terms',
            'items': prod_mgr_pending_comp_terms,
            'url': url,
        }
    return None


def get_developer_pending_comp_terms_task(user, pkgs):
    developer_pending_comp_terms = pkgs.filter(
        assigned_to=user,
        dev_compterms_validation=CTConfirmStatusEnum.PENDING,
        status__in=['CONFIRM CT'],
        release__is_locked=False,
    )
    developer_pending_comp_terms = developer_pending_comp_terms.count()

    if developer_pending_comp_terms:
        url = (
            "#/compliance-terms?assigned_to__id={}&"
            "order_by=master_ticket__name&status__in=CONFIRM CT&"
            "dev_compterms_validation__in=PENDING ACCEPTANCE&"
            "_persona=developer"
        ).format(user.id)
        return {
            'name': 'Unconfirmed Developer Compliance Terms',
            'items': developer_pending_comp_terms,
            'url': url
        }
    return None


def get_releases_ga_unlocked_list_task(user):
    filter_cond = Q(licensereviewticket__release__owners__release_mgr=user)
    filter_cond |= Q(licensereviewticket__release__owners__eng_mgr=user)
    filter_cond |= Q(licensereviewticket__release__owners__product_mgr=user)
    filter_cond |= Q(licensereviewticket__release__release_cc_rel__user__in=[user])

    releases_ga_unlocked_list = LicenseReviewTicketAttachments.objects.filter(
        filename__startswith='open_source_license_',
        filename__endswith='GA.txt'
    ).filter(
        filter_cond,
        licensereviewticket__release__enabled=True,
        licensereviewticket__release__is_locked=False
    ).values_list(
        'licensereviewticket__release__id',
        flat=True
    ).distinct()

    if releases_ga_unlocked_list.exists():
        url = (
            "#/release?release_type=OSM&"
            "release_id__in={}"
        ).format(','.join(str(x) for x in releases_ga_unlocked_list))
        return {
            'name': 'OSM Releases that need to be locked',
            'items': releases_ga_unlocked_list.count(),
            'url': url
        }
    return None


def get_unmapped_blackduck_licenses_task(user):
    if not user.groups.filter(name='legal').exists():
        return None
    unmapped_blackduck_licenses = HubLicense.objects.filter(
        mapped=False,
    ).count()

    if unmapped_blackduck_licenses:
        url = "#/hub-license?mapped=false"

        return {
            'name': 'Unmapped Scanned Licenses',
            'items': unmapped_blackduck_licenses,
            'url': url,
        }
    return None


def get_need_fill_lic_expiration_date_pkgs_task(user, pkgs):
    """
    pkgs: active use package queryset
    get the link of active pkgs which is licensed under a 3rd license:
      'TP-Paid-Company', 'TP-Paid-Product', 'TP-Paid-User'
    """
    q = Q(reporter=user)
    q |= Q(release__owners__product_mgr=user)
    q |= Q(release__owners__eng_mgr=user)
    q |= Q(release__owners__release_mgr=user)
    q |= Q(release__cc=user)
    tp_pkgs = pkgs.filter(
        q,
        license__value__in=License.TP_LICS,
        license_expiration_date__isnull=True,
        tp_license_perpetual=False,
        release__is_locked=False
    ).distinct('id')
    if tp_pkgs.exists():
        url = (
            "#/package?"
            "id__in={}"
        ).format(','.join(
            [str(i) for i in tp_pkgs.order_by('id').values_list('id', flat=True)])
        )
        return {
            'name': 'Third-party packages missing an expiration date',
            'items': tp_pkgs.count(),
            'url': url,
            'desc': 'Go to the package detail page(OSPO tab) to fill the field: Expire Date'
        }
    return None


def get_tp_pkgs_is_going_to_be_expired(user, pkgs):
    q = Q(reporter=user)
    q |= Q(release__owners__product_mgr=user)
    q |= Q(release__owners__eng_mgr=user)
    q |= Q(release__owners__release_mgr=user)
    q |= Q(release__cc=user)
    two_month = datetime.timedelta(days=60)
    today = datetime.date.today()
    tp_pkgs = pkgs.filter(
        q,
        license__value__in=License.TP_LICS,
        license_expiration_date__lt=today + two_month,
        tp_license_perpetual=False,
        release__is_locked=False
    ).distinct('id')
    if tp_pkgs.exists():
        url = (
            "#/package?"
            "id__in={}"
        ).format(','.join(
            [str(i) for i in tp_pkgs.order_by('id').values_list('id', flat=True)])
        )
        return {
            'name': 'Third-party packages going to be expired',
            'items': tp_pkgs.count(),
            'url': url,
            'desc': ('Go to the package detail page(OSPO tab) to update the '
                     'License Expiration Date or resolve the package as NON-ISSUE')
        }
    return None


def get_dev_newer_version_pkgs_task(user, pkgs):
    dev_newer_version_pkgs = pkgs.filter(
        assigned_to=user,
        master_ticket__has_newer_version=True,
        new_version_ignored=False,
        release__is_locked=False,
    ).values_list(
        'id',
        flat=True
    )

    if dev_newer_version_pkgs:
        url = (
            "#/package?id__in={}"
        ).format(','.join(str(x) for x in dev_newer_version_pkgs))
        return {
            'name': 'Packages assigned to you which may be upgraded',
            'items': len(dev_newer_version_pkgs),
            'url': url,
        }
    return None


def get_pm_newer_version_releases(user, pkgs):
    owner_cond = Q(release__owners__release_mgr=user)
    owner_cond |= Q(release__owners__eng_mgr=user)
    owner_cond |= Q(release__owners__product_mgr=user)

    pm_newer_version_pkgs = pkgs.filter(
        owner_cond,
        master_ticket__has_newer_version=True,
        new_version_ignored=False,
        release__is_locked=False,
    )

    pm_newer_version_releases = pm_newer_version_pkgs.values_list(
        'release__id', 'release__product__name', 'release__name').distinct()

    if pm_newer_version_releases:
        task = {
            'name': 'Packages in your releases that can be upgraded',
            'items': [],
        }
        for release in pm_newer_version_releases:
            newer_version_pkgs_in_releases = pkgs.filter(
                release__id=release[0],
                master_ticket__has_newer_version=True,
                new_version_ignored=False,
            ).values_list(
                'id',
                flat=True
            )
            url = (
                "#/package?id__in={}"
            ).format(','.join(str(x) for x in newer_version_pkgs_in_releases))
            task['items'].append({
                'name': "{0} {1}".format(release[1], release[2]),
                'items': len(newer_version_pkgs_in_releases),
                'url': url,
            })
        return task
    return None

def get_releases_without_mapping(user):
    rmrelease_owner_Q = Q(release__owners__release_mgr=user)
    rmrelease_owner_Q |= Q(release__owners__eng_mgr=user)
    rmrelease_owner_Q |= Q(release__owners__product_mgr=user)

    release_owner_Q = Q(owners__release_mgr=user)
    release_owner_Q |= Q(owners__eng_mgr=user)
    release_owner_Q |= Q(owners__product_mgr=user)

    releases_with_mapping_list = RMRelease_Mapping.objects.filter(
        rmrelease_owner_Q,
        release__enabled=True,
        release__is_locked=False,
        release__created__gte=datetime.date.today() - datetime.timedelta(days=3*365)
    ).values_list(
        'release__id',
        flat=True
    ).distinct()

    all_releases_by_owner_list = Release.objects.filter(
        release_owner_Q,
        enabled=True,
        is_locked=False,
        created__gte=datetime.date.today() - datetime.timedelta(days=3*365)
    ).exclude(
        not_distributed_external=True
    ).values_list(
        'id',
        flat=True
    ).distinct()

    releases_without_mapping_list = list(
        set(all_releases_by_owner_list) - set(releases_with_mapping_list)
    )

    if releases_without_mapping_list:
        url = (
            "#/release?release_type=OSM&release_id__in={}"
        ).format(','.join(str(x) for x in releases_without_mapping_list))
        return {
            'name': 'OSM Releases that need to be mapped to BOSSD',
            'items': len(releases_without_mapping_list),
            'url': url
        }
    return None

def get_java_oracle_usage(user, pkgs):
    """
    pkgs: active use package queryset
    get the link of active pkgs which is licensed under a 3rd license:
      'TP-Paid-Company', 'TP-Paid-Product', 'TP-Paid-User'
    """
    q = Q(reporter=user)
    q |= Q(release__owners__product_mgr=user)
    q |= Q(release__owners__eng_mgr=user)
    q |= Q(release__owners__release_mgr=user)
    q |= Q(release__cc=user)
    tp_pkgs = pkgs.filter(
        q,
        Q(master_ticket__name__icontains='jre')|Q(master_ticket__name__icontains='jdk'),
        license__value='TP-Paid-Company',
        license_expiration_date__isnull=True,
        tp_license_perpetual=False,
        release__is_locked__exact=False
    ).distinct('id')
    if tp_pkgs.exists():
        url = (
            "#/package?"
            "id__in={}"
        ).format(','.join(
            [str(i) for i in tp_pkgs.order_by('id').values_list('id', flat=True)])
        )
        return {
            'name': 'java or oracle use',
            'items': tp_pkgs.count(),
            'url': url,
            'desc': 'Go to the package detail page(OSPO tab) to fill the field: Expire Date'
        }
    return None


def get_uncompleted_uc_tasks(self):
    user_tasks = {}
    if self.groups.filter(name='legal'):
        task1 = get_new_assigned_projects_task(self)
        if task1:
            user_tasks['new_assigned_projects'] = task1
        task2 = get_new_assigned_contributions_task(self)
        if task2:
            user_tasks['new_assigned_contributions'] = task2
        task3 = get_private_repo_review_requested_task()
        if task3:
            user_tasks['private_repo_review_requested'] = task3
        task4 = get_potential_unmapped_projects_task()
        if task4:
            user_tasks['get_potential_unmapped_projects'] = task4
    else:
        task5 = get_approved_project_can_create_repo_task(self)
        if task5:
            user_tasks['approved_project_can_create_repo'] = task5
        task6 = get_approved_private_repo_can_made_public_task(self)
        if task6:
            user_tasks['approved_private_repo_can_made_public'] = task6
        task7 = get_assigned_open_projects_task(self)
        if task7:
            user_tasks['assigned_open_projects'] = task7
        task8 = get_assigned_open_contributions_task(self)
        if task8:
            user_tasks['assigned_open_contributions'] = task8

    return user_tasks or None

def get_new_assigned_projects_task(user):
    assignee = [user.username, settings.OSPO_CONTACT]
    projects = scot_models.OssProjectTicket.objects.filter(
        status=UCTicketStateEnum.NEW,
        assigned_to__username__in=assignee
    ).count()

    if projects:
        return {
            'name': '<b>New Project Tickets</b><br/>Assigned to you',
            'items': projects,
            'url': ('#/upstreamcontrib/project?'
                    'assigned_to__username__in={}&'
                    'status__in=NEW').format(','.join(assignee)),
        }
    return None

def get_new_assigned_contributions_task(user):
    assignee = [user.username, settings.OSPO_CONTACT]
    contributions = scot_models.ContributionTicket.objects.filter(
        status=UCTicketStateEnum.NEW,
        assigned_to__username__in=assignee
    ).count()

    if contributions:
        return {
            'name': '<b>New Contribution Tickets</b><br/>Assigned to you',
            'items': contributions,
            'url': ('#/upstreamcontrib/contribution?'
                    'assigned_to__username__in={}&'
                    'status__in=NEW').format(','.join(assignee)),
        }
    return None

def get_private_repo_review_requested_task():
    repos = GitHubRepoDashboard.objects.filter(
        repo__request_status__in=[RepoRequestStatus.UNDER_REVIEW.value],
        repo__gh_status__in=[RepoGitHubStatus.PRIVATE.value],
    ).count()

    if repos:
        return {
            'name': '<b>Private Repo Review</b>',
            'items': repos,
            'url': ('#/upstreamcontrib/repository?'
                    'repo__request_status__in=UNDER REVIEW&'
                    'repo__gh_status__in=PRIVATE'),
        }
    return None

def get_potential_unmapped_projects_task():
    """
     Try the best guess:
     1.find (not-archived) migrated repos, get the name list
     2.find vmw-projects have no linked repo, and name in the migrated list
    """
    migrated_repos = GitHubRepo.objects.filter(
        request_status=RepoRequestStatus.MIGRATED.value,
        gh_status__in=[RepoGitHubStatus.PRIVATE.value, RepoGitHubStatus.PUBLIC.value]
    ).values_list('name', flat=True)

    projects = OssProjectTicket.objects.filter(
        repo__isnull=True,
        repository__in=migrated_repos,
        status=UCTicketStateEnum.RESOLVED,
        resolution=UCTicketResolutionEnum.APPROVED,
        project_type=OssProjectType.VMW_PROJECT.value
    )
    count = projects.count()
    if count:
        return {
            'name': 'Projects have <b>potential repos</b> for mapping',
            'items': count,
            'url': ('#/upstreamcontrib/project?project_type__in=vmw_project&'
                    'repo__isnull=True&status__in=RESOLVED&resolution__in=APPROVED&repository__in={}'
                    ).format(','.join(projects.values_list('repository', flat=True))),
        }
    return None

def get_approved_project_can_create_repo_task(user):
    projects = scot_models.OssProjectTicket.objects.filter(
        project_type=OssProjectType.VMW_PROJECT.value,
        status=UCTicketStateEnum.RESOLVED,
        resolution=UCTicketResolutionEnum.APPROVED,
        project_owner=user,
        repo__isnull=True
    ).exclude(repository='').count()

    if projects:
        return {
            'name': '<b>Project Approved</b><br/>Private repo can now be created',
            'items': projects,
            'url': ('#/upstreamcontrib/project?project_type__in=vmw_project&'
                    'status__in=RESOLVED&resolution__in=APPROVED&'
                    'repo__isnull=True&has_repository=True&project_owner__username__in={}'
                    ).format(user.username),
        }
    return None

def get_approved_private_repo_can_made_public_task(user):
    repos = GitHubRepoDashboard.objects.filter(
        repo__request_status__in=[RepoRequestStatus.APPROVED.value],
        repo__gh_status__in=[RepoGitHubStatus.PRIVATE.value],
        repo__vmw_origin_project__project_owner=user,
    ).count()

    if repos:
        return {
            'name': '<b>Private Repos Approved</b><br/>Can now be made public',
            'items': repos,
            'url': ('#/upstreamcontrib/repository?repo__request_status__in=APPROVED&'
                    'repo__gh_status__in=PRIVATE&'
                    'repo__vmw_origin_project__project_owner__username__in={}').format(user.username),
        }
    return None

def get_assigned_open_projects_task(user):
    status = [
        UCTicketStateEnum.NEW,
        UCTicketStateEnum.ASSIGNED,
        UCTicketStateEnum.ON_HOLD
    ]
    projects = scot_models.OssProjectTicket.objects.filter(
        status__in=status,
        assigned_to=user
    ).count()

    if projects:
        return {
            'name': '<b>Open Project Tickets</b><br/>Assigned to Me',
            'items': projects,
            'url': ('#/upstreamcontrib/project?'
                    'assigned_to__username__in={}&'
                    'status__in={}').format(user.username, ','.join(status)),
        }
    return None

def get_assigned_open_contributions_task(user):
    status = [
        UCTicketStateEnum.NEW,
        UCTicketStateEnum.ASSIGNED,
        UCTicketStateEnum.ON_HOLD
    ]
    contributions = scot_models.ContributionTicket.objects.filter(
        status__in=status,
        assigned_to=user
    ).count()

    if contributions:
        return {
            'name': '<b>Open Contribution Tickets</b><br/>Assigned to Me',
            'items': contributions,
            'url': ('#/upstreamcontrib/contribution?'
                    'assigned_to__username__in={}&'
                    'status__in={}').format(user.username, ','.join(status)),
        }
    return None

@property
def format_str(self):

    if (not self.first_name) and (not self.last_name):
        return self.username

    return u'{0} {1} ({2})'.format(
        self.first_name,
        self.last_name,
        self.username
    )

@property
def is_legal(self):
    return self.groups.filter(name=UserProfile.LEGAL).exists()

@property
def is_security(self):
    return self.groups.filter(name=UserProfile.SECURITY).exists()

@property
def full_name(self: "User"):
    name: "str" = f"{self.first_name} {self.last_name}"
    if not name.strip():
        name = self.username
    return name


# Monkey Patching is the best option for adding methods to the User class
User.add_to_class("get_users_below_user", get_users_below_user)
User.add_to_class("get_uncompleted_tasks", get_uncompleted_tasks)
User.add_to_class("get_uncompleted_uc_tasks", get_uncompleted_uc_tasks)
User.add_to_class("format_str", format_str)
User.add_to_class("is_legal", is_legal)
User.add_to_class("is_security", is_security)
User.add_to_class("full_name", full_name)


class UserProfile(models.Model):
    DEVELOPER = 'developer'
    ENG_MGR = 'dev-manager'
    PROD_MGR = 'product-manager'
    REL_MGR = 'release-management'
    LEGAL = 'legal'
    SECURITY = 'security'
    PERSONA_OPTIONS = (
        (DEVELOPER, 'Developer'),
        (ENG_MGR, 'Engineering Manager'),
        (PROD_MGR, 'Product Manager'),
        (REL_MGR, 'Release Manager'),
        (LEGAL, 'Legal'),
        (SECURITY, 'Security'),
    )

    """
    Definition of user Django profile: additional information on users.
    """
    user = models.OneToOneField(
        User,
        related_name='profile',
        on_delete=models.CASCADE,
        help_text="User associated with the profile",
    )
    disabledtext = models.TextField(
        blank=True,
        help_text="If non-empty, the reason the user has been disabled",
    )
    disable_mail = models.SmallIntegerField(
        default=0,
        help_text="Should e-mail for this user be disabled",
    )
    mybugslink = models.SmallIntegerField(
        default=0,
        help_text="Historical field, un-used in the context SCOTzilla",
    )
    employee_number = models.CharField(
        unique=True,
        null=True,
        max_length=64,
        help_text="Unique identifier for a person, employee id",
    )
    sync_exempt = models.BooleanField(
        default=False,
        help_text="Should LDAP synchronization ignore this user?",
    )
    title = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Person's work title",
    )
    realname = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="The user's real name",
    )
    telephone = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Person's telephone number (work)",
    )
    manager = models.ForeignKey(
        User,
        null=True,
        related_name='+',
        on_delete=models.CASCADE,
        help_text="User manager",
    )
    department = models.ForeignKey(
        scot_models.Department,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        help_text="The person's department",
    )
    business_unit = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Business Unit for the user",
    )
    office = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Office (location) for the user",
    )
    city = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="City the user is located in",
    )
    state = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="State within the country, if applicable, for the user",
    )
    country = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Country (location) for the user",
    )
    saved_state = models.TextField(
        default="",
        blank=True,
        help_text="This stores a json string of a users saved state",
    )
    timezone = models.CharField(
        max_length=255,
        default="America/Los_Angeles",
        help_text="The user's timezone",
    )
    # Email Settings
    notify_time = models.TimeField(
        max_length=32,
        default=datetime.time(10, 0, 0),
        help_text="When to receive your daily notifications",
    )
    # Store the utc time, so we don't have to convert it when sending
    # emails
    notify_time_utc = models.TimeField(
        max_length=32,
        default=datetime.time(18, 0, 0),
        help_text="UTC of when to receive your daily notifications",
    )
    save_next = models.BooleanField(
        default=False,
        help_text="Should you be redirected to the next item when click save button",
    )
    debug_super = models.BooleanField(
        default=False,
        help_text='Whether the user should be considered as a superuser in debug env, in order to perform '
                  'directly creating product, approving release, etc.'
    )

    class Meta:
        app_label = 'user'

    def __str__(self):
        """
        Convert to a string.  Include real name if one exists.
        """
        if self.realname:
            return "{0} <{1}>".format(self.realname, str(self.user))
        return str(self.user)

    def set_timezone(self):
        self.timezone = utils.get_timezone(self.office)
        self.save()

    # pylint: disable=arguments-differ
    def save(self, *args, **kwargs):
        # Need to save the utc time according to the users timezone
        # If not new
        if self.pk:
            original = UserProfile.objects.get(pk=self.pk)
            if (original.notify_time != self.notify_time or
                    original.timezone != self.timezone):
                try:
                    self.notify_time_utc = str(
                        datetime.datetime.now(
                            pytz.timezone(self.timezone)
                        ).replace(
                            hour=self.notify_time.hour, minute=0, second=0,
                            microsecond=0
                        ).astimezone(pytz.utc).time())
                except:
                    print(self.user)
                    print(self.office)
                    print(utils.get_timezone(self.office))
                    raise
        super().save(*args, **kwargs)


User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])


class SavedSearches(models.Model):

    """
    Where users store filtered results so that they don't have to apply
    filters everytime they login, they can apply one of theses saved
    SavedSearches to the tableList
    """

    owner = models.ForeignKey(
        User,
        db_index=True,
        on_delete=models.CASCADE,
    )

    url = models.TextField(
        null=True,
        blank=False,
        help_text="The url that stores the saved search",
    )

    name = models.CharField(
        max_length=255,
        null=True,
        blank=False,
        help_text="The name of the saved search",
    )

    date_created = models.DateTimeField(auto_now_add=True, db_index=True)

    last_updated = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        app_label = 'user'

    def __str__(self):
        return '{0}: {1}'.format(str(self.name), self.owner)

class UserGroup:
    ENG_MGR = 'dev-management'
    PROD_MGR = 'product-management'
    REL_MGR = 'release-management'
    SECURITY = 'security'
    LEGAL = 'legal'
