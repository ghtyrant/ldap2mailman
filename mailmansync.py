#!/usr/bin/python

import ldap
import logging
import pprint
import subprocess
import argparse
import getpass
import base64
import random
import string
import sys
from collections import namedtuple
from ConfigParser import SafeConfigParser, NoOptionError

# Default lookup path for configuration
CONFIG_FILE='/etc/mailmansync.ini'

# Length of generated passwords
PW_LENGTH=12

# Alphabet used for generating passwords
PW_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits


def execute(params, stdin_data=""):
    """Executes a binary, writes stdin_data to its stdin and returns returncode and stdout."""
    logging.debug("Executing binary: '%s'" % (' '.join(params)))
    p = subprocess.Popen(params, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout,stderr) = p.communicate(input=stdin_data)

    if stderr:
        stdout += "\nstderr:\n" + stderr

    return (p.returncode, stdout)

def read_config(path):
    """
    Reads a config file that maps ldap groups to mailman groups.
    Format:

        # <ldap query string> <mailman group name>
        cn=stv_bits,ou=Student Councils bits

        # Both parts can be seperated by multiple spaces/tabs
        cn=my_cn,ou=Useless Groups          mymailman_group

    Spaces are okay, as long as the mailman group name is the last word in a line.
    """

    groups = []
    Group = namedtuple("Group", ["mailman_group", "member_query", "search_base", "group_search_base", "fetch_admin", "list_admin", "ldap_group"])

    parser = SafeConfigParser({"ldap_group": "", "ldap_password": None})
    parser.read(path)

    for section in parser.sections():
        if section == "core":
            continue

        groups.append(Group(mailman_group=section,
                            ldap_group=parser.get(section, "ldap_group"),
                            member_query=parser.get(section, "member_query"),
                            search_base=parser.get(section, "search_base"),
                            group_search_base=parser.get(section, "group_search_base"),
                            fetch_admin=parser.getboolean(section, "fetch_admin"),
                            list_admin=parser.get(section, "list_admin")))

    try:
        host = parser.get("core", "ldap_host")
        user = parser.get("core", "ldap_user")
    except NoOptionError as e:
        logging.error("Missing configuration option: %s" % (e))
        sys.exit(-1)

    password = parser.get("core", "ldap_password", None)

    if password and password.startswith("{base64}"):
        password = base64.b64decode(password[8:]).strip()

    return (host, user, password), groups

def add_members(group, mails, dry_run=False):
    """Runs mailman's add_members, adding only new mails to a list.

    add_members
    -n (Dry run)
    -w n (No welcome msg)
    -a n (No admin notification)
    -r - (Read regular users from stdin)
    <listname>

    """

    # add_members has no dry-run, so we'll just not run it at all
    if not dry_run:
        (returncode, stdout) = execute(["/usr/lib/mailman/bin/add_members", "-w", "n", "-a", "n", "-r", "-", group], "\n".join(mails))
    else:
        stdout = "add_members(): Dry run, not actually adding the following mails:\n%s" % ("\n".join(mails))
        returncode = 0

    return (returncode, stdout)

def sync_members(group, mails, dry_run=False):
    """Runs mailman's sync_members, syncing members of a list.

    sync_members
    -n (Dry run)
    -w=no (No welcome msg)
    -g=no (No goodbye msg)
    -d=no (No digest)
    -a=no (No admin notification)
    -f - (Read from stdin)
    <listname>

    """

    return execute(["sync_members", "-n" if dry_run else "", "-w=no", "-g=no", "-d=no", "-a=no", "-f", "-", group], "\n".join(mails))

def update_admin(group, mail, dry_run=False):
    """
    Runs mailman's config_list and change_pw by generating a config file that is read by config_file
    and a random password that is then set by change_pw, automatically informing the list's admin."""

    temp_path = "/tmp/mailmansync_admin"

    # Get mailman to puke a lists config into a temp-file
    (returncode, stdout) = execute(["/usr/lib/mailman/bin/config_list", "-o", temp_path, group])

    if returncode != 0:
        logging.error("config_list failed: '%s'" % (stdout))
        return False

    config = {}
    execfile(temp_path, config)

    if "owner" not in config:
        logging.error("No 'owner' in auto generated config for list '%s'!" % (group))
        return False

    # Now check if the new admin is already in the owner list
    if mail in config["owner"]:
        # Owner is already present, we do nothing
        logging.debug("Owner for list '%s' hasn't changed, no update required." % (group))
        return True

    with open(temp_path, "w") as stream:
        stream.write("owner=['%s']" % (mail))

    config_list_call = ["/usr/lib/mailman/bin/config_list", "-i", temp_path]
    if dry_run:
        config_list_call.append("-c")
    config_list_call.append(group)
    (returncode, stdout) = execute(config_list_call)

    if returncode != 0:
        logging.error("config_list failed: '%s'" % (stdout))
        return False

    if not dry_run:
        rng = random.SystemRandom
        pw = str().join([rng(random).choice(PW_ALPHABET) for i in range(PW_LENGTH)])

        (returncode, stdout) = execute(['/usr/lib/mailman/bin/change_pw', '-l', group, '-p', pw])

        if returncode != 0:
            logging.error("change_pw failed: '%s'" % (stdout))
            return False

    return True

def fetch_members(host, user, password, groups, sync=True, dry_run=False):
    """
    Fetches all members of the LDAP groups used as keys in the map 'groups' and then calls either add_members or sync_members."""

    # AD somehow fucks up initial referrals with simple binding, I don't even ...
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    l = ldap.initialize(host)

    # methods ending in _s are synchronous (blocking)
    l.simple_bind_s(user, password)
    total_count = 0

    if sync:
        logging.info("Synchronizing lists, members will be deleted eventually!")
    else:
        logging.info("Only adding new members to lists, no one will be deleted!")

    for group in groups:
        mails = []
        synced_count = 0

        logging.debug("Fetching '%s' (Search base: '%s', query: '%s'..." % (group.mailman_group, group.search_base, group.member_query))
        r = l.search_ext_s(group.search_base, ldap.SCOPE_SUBTREE, group.member_query, ['cn', 'mail'])

        if not r:
            logging.warn("LDAP-Query yielded no results, possibly a typo in the config file? Skipping! (mailman group: '%s', full query: '%s')"
                         % (group.mailman_group, group.member_query))
            continue

        for dn, entry in r:

            # this won't happen (i think)
            if not 'cn' in entry:
                logging.debug("   - Weird LDAP entry, no cn!")
                pprint.pprint(entry)
                continue

            if not 'mail' in entry:
                logging.debug("   - Skipping '%s', no mail address specified." % (entry['cn'][0]))
                continue

            for mail in entry['mail']:
                synced_count += 1
                mail = mail.lower()

                mails.append(mail)

        logging.debug("Group '%s' has the following members %s." % (group.mailman_group, mails))
        if sync:
            (returncode, stdout) = sync_members(group.mailman_group, mails, dry_run)
        else:
            (returncode, stdout) = add_members(group.mailman_group, mails, dry_run)

        if stdout:
            logging.debug("Mailman says: '%s'" % (stdout))

        # Get the lists admin

        group_manager = ""
        if group.fetch_admin:
            if group.ldap_group:

                group_cn = group.ldap_group.split(",")[0]
                managers = l.search_ext_s(group.group_search_base, ldap.SCOPE_SUBTREE, group_cn, ['managedBy'])

                if managers:
                    for dn, entry in managers:
                        users = l.search_ext_s(entry["managedBy"][0], ldap.SCOPE_SUBTREE, "(objectClass=*)", ['cn', 'mail'])

                        if not users:
                            logging.error("User '%s' not found! This should not happen." % (entry["managedBy"]))
                        else:
                            user = users[0]
                            group_manager = user[1]["cn"][0]
                            logging.debug("Setting user '%s' as group admin for group '%s'." % (user[1]["cn"][0], group.mailman_group))
            else:
                logging.warn("Group '%s' set to automatically fetch manager, yet ldap_group is not defined (Search base: '%s')!" % (
                             group.mailman_group,
                             group.group_search_base))

        if not group_manager:
            logging.info("Group '%s' has no manager (Search base: '%s'), defaulting to '%s'!" % (group.mailman_group, group.group_search_base, group.list_admin))
            group_manager = group.list_admin

        update_admin(group.mailman_group, group.list_admin, dry_run)


        total_count += synced_count
        logging.debug("Synced %d mail addresses with group %s." % (synced_count, group.mailman_group))

    l.unbind_s()

def main(args):
    level = logging.DEBUG

    if args.cron:
        level = logging.WARN

    if args.debug:
        level = logging.DEBUG

    logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s", level=level)

    (host, user, password), groups = read_config(CONFIG_FILE if not args.config else args.config)
    if not password:
        password = getpass.getpass("LDAP-Password (%s): " % (user))

    fetch_members(host, user, password, groups, args.sync, args.dry_run)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Sync LDAP users with mailman.')
    parser.add_argument("--dry-run", action='store_true', help='Do not actually update anything, just log')
    parser.add_argument("--cron", action='store_true', help='Run as a cron job. Suppress output and don\'t ask for stuff')
    parser.add_argument("--debug", action='store_true', help='Set log level to DEBUG')
    parser.add_argument("--sync", action='store_true', help='Fully synchronize lists, including removal of members if needed.')
    parser.add_argument("-c", "--config", type=str, help='Path to configuration file.')
    main(parser.parse_args())
