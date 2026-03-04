from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry
from datetime import datetime, timedelta, timezone
import sys


class NXCModule:
    """
    Lists enabled computer accounts whose pwdLastSet is older than supplied DAYS.
    """

    name = "stale-computers"
    description = "Lists enabled computer accounts with pwdLastSet older than supplied DAYS"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        DAYS        Number of days to check pwdLastSet against (required)
        SAM         Print only sAMAccountName (True/False, default: False)

        Example:
        nxc ldap <target> -u user -p pass -M stale-computers -o DAYS=30
        nxc ldap <target> -u user -p pass -M stale-computers -o DAYS=30,SAM=True
        """

        if not module_options or "DAYS" not in module_options:
            context.log.fail("DAYS option is required")
            sys.exit(1)

        try:
            self.DAYS = int(module_options["DAYS"])
        except ValueError:
            context.log.fail("DAYS must be an integer")
            sys.exit(1)

        self.SAM = False
        if "SAM" in module_options:
            if module_options["SAM"] == "True":
                self.SAM = True
            elif module_options["SAM"] == "False":
                self.SAM = False
            else:
                context.log.fail("SAM must be True or False")
                sys.exit(1)

    def filetime_to_dt(self, filetime):
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(filetime) / 10)

    def on_login(self, context, connection):

        search_filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        try:
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=["dNSHostName", "sAMAccountName", "pwdLastSet"],
                sizeLimit=0
            )
        except LDAPSearchError as e:
            if "sizeLimitExceeded" in e.getErrorString():
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.DAYS)
        found = False

        for item in resp:
            if not isinstance(item, SearchResultEntry):
                continue

            hostname = None
            sam = None
            pwd_last_set_raw = None

            for attribute in item["attributes"]:
                attr_type = str(attribute["type"])

                if attr_type == "dNSHostName":
                    hostname = str(attribute["vals"][0])
                elif attr_type == "sAMAccountName":
                    sam = str(attribute["vals"][0])
                elif attr_type == "pwdLastSet":
                    pwd_last_set_raw = str(attribute["vals"][0])

            if not pwd_last_set_raw or pwd_last_set_raw == "0":
                continue

            pwd_dt = self.filetime_to_dt(pwd_last_set_raw)

            if pwd_dt < cutoff:
                if not found:
                    context.log.success(
                        f"Enabled computers with pwdLastSet older than {self.DAYS} days:"
                    )
                    found = True

                if self.SAM:
                    if sam:
                        context.log.highlight(f"{sam}")
                else:
                    if hostname:
                        context.log.highlight(f"{hostname} - pwdLastSet: {pwd_dt}")

        if not found:
            context.log.success("No matching computer accounts found.")
